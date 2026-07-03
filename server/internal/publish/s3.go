package publish

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// S3Store publishes snapshots to an S3-compatible object store (AWS S3, MinIO,
// Ceph RGW, ...). It is a deliberately minimal client — SigV4-signed PUT/GET
// over net/http, reusing the AWS SDK's signer and credential chain already in
// the dependency tree — rather than the full S3 service module, whose
// checksum/negotiation behaviors are a known interop hazard with non-AWS
// stores.
//
// Object stores offer no multi-key atomicity, so the snapshot contract is
// manifest-last: artifacts are uploaded first (concurrently) and manifest.json
// is only written once every artifact upload succeeded. Consumers that resolve
// artifact sets through the manifest therefore never observe a partial
// snapshot; consumers fetching individual CRL/OCSP objects observe per-object
// atomic replacement (S3 PUT semantics). Integrity is enforced per object: each
// PUT carries a Content-MD5 the server verifies before committing, and the
// returned ETag is compared against the local digest.
type S3Store struct {
	cfg    S3Config
	creds  aws.CredentialsProvider
	signer *v4.Signer
	client *http.Client
}

// S3Config configures the S3 backend.
type S3Config struct {
	// Endpoint is the base URL of an S3-compatible service (e.g.
	// http://minio:9000). Empty targets AWS S3 in Region.
	Endpoint string
	// Region is the signing region. Empty defaults to us-east-1.
	Region string
	// Bucket is the destination bucket (required).
	Bucket string
	// Prefix is prepended to every object key (optional).
	Prefix string
	// AccessKeyID / SecretAccessKey / SessionToken are static credentials. When
	// AccessKeyID is empty the default AWS credential chain (environment, shared
	// config, IAM role) is used instead.
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// ForcePathStyle addresses the bucket in the URL path rather than the host.
	// Path style is applied automatically when Endpoint is set (the norm for
	// S3-compatible stores); this forces it for AWS too.
	ForcePathStyle bool
	// Concurrency bounds parallel artifact uploads (default 8).
	Concurrency int
	// HTTPClient overrides the transport (tests). Nil uses a client with sane
	// timeouts.
	HTTPClient *http.Client
}

// NewS3Store validates the configuration and resolves the credential source.
func NewS3Store(ctx context.Context, cfg S3Config) (*S3Store, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3 publish backend requires a bucket")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.Endpoint != "" {
		u, err := url.Parse(cfg.Endpoint)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid s3 endpoint %q", cfg.Endpoint)
		}
		cfg.ForcePathStyle = true
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}

	var creds aws.CredentialsProvider
	if cfg.AccessKeyID != "" {
		creds = credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken)
	} else {
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
		if err != nil {
			return nil, fmt.Errorf("resolving AWS credentials: %w", err)
		}
		creds = awsCfg.Credentials
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &S3Store{cfg: cfg, creds: aws.NewCredentialsCache(creds), signer: v4.NewSigner(), client: client}, nil
}

// Name identifies the backend.
func (s *S3Store) Name() string { return "s3" }

// Publish uploads every artifact (bounded concurrency), then the manifest.
func (s *S3Store) Publish(ctx context.Context, manifest []byte, artifacts []Artifact) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan *Artifact)
	errCh := make(chan error, s.cfg.Concurrency)
	var wg sync.WaitGroup
	for w := 0; w < s.cfg.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				if err := s.put(ctx, a.Path, a.Data, a.ContentType); err != nil {
					select {
					case errCh <- fmt.Errorf("uploading %s: %w", a.Path, err):
					default:
					}
					cancel() // stop feeding; the manifest must not be written
					return
				}
			}
		}()
	}

feed:
	for i := range artifacts {
		select {
		case jobs <- &artifacts[i]:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Manifest strictly last: it marks the snapshot complete.
	if err := s.put(ctx, ManifestPath, manifest, "application/json"); err != nil {
		return fmt.Errorf("uploading manifest: %w", err)
	}
	return nil
}

// Fetch reads one published object.
func (s *S3Store) Fetch(ctx context.Context, p string) ([]byte, error) {
	if err := checkRelPath(p); err != nil {
		return nil, fmt.Errorf("invalid path %q: %w", p, err)
	}
	req, err := s.newSignedRequest(ctx, http.MethodGet, p, nil, "")
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s: %s", p, resp.Status, truncate(body, 256))
	}
	return body, nil
}

// etagMD5 matches a plain (non-multipart) S3 ETag, which is the object's MD5.
var etagMD5 = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

// put uploads one object with Content-MD5 integrity, retrying transient
// failures. The server rejects the write if the body does not match the MD5;
// the returned ETag is additionally compared when it carries a plain digest.
func (s *S3Store) put(ctx context.Context, p string, data []byte, contentType string) error {
	sum := md5.Sum(data)
	contentMD5 := base64.StdEncoding.EncodeToString(sum[:])
	wantETag := hex.EncodeToString(sum[:])

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
		req, err := s.newSignedRequest(ctx, http.MethodPut, p, data, contentType, header{"Content-MD5", contentMD5})
		if err != nil {
			return err
		}
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			etag := strings.Trim(resp.Header.Get("ETag"), `"`)
			if etagMD5.MatchString(etag) && !strings.EqualFold(etag, wantETag) {
				return fmt.Errorf("integrity check failed: ETag %s != md5 %s", etag, wantETag)
			}
			return nil
		case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
			lastErr = fmt.Errorf("PUT %s: %s: %s", p, resp.Status, truncate(body, 256))
			continue
		default:
			return fmt.Errorf("PUT %s: %s: %s", p, resp.Status, truncate(body, 256))
		}
	}
	return lastErr
}

type header struct{ key, value string }

// newSignedRequest builds and SigV4-signs one S3 request.
func (s *S3Store) newSignedRequest(ctx context.Context, method, p string, body []byte, contentType string, extra ...header) (*http.Request, error) {
	u, err := s.objectURL(p)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for _, h := range extra {
		req.Header.Set(h.key, h.value)
	}
	payloadHash := sha256.Sum256(body) // sha256 of empty slice for GET
	hashHex := hex.EncodeToString(payloadHash[:])
	req.Header.Set("x-amz-content-sha256", hashHex)

	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieving AWS credentials: %w", err)
	}
	if err := s.signer.SignHTTP(ctx, creds, req, hashHex, "s3", s.cfg.Region, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("signing request: %w", err)
	}
	return req, nil
}

// objectURL builds the object URL for a snapshot path, path-style or
// virtual-hosted per configuration.
func (s *S3Store) objectURL(p string) (string, error) {
	key := p
	if s.cfg.Prefix != "" {
		key = path.Join(strings.Trim(s.cfg.Prefix, "/"), p)
	}
	// Escape each key segment; '/' separators stay literal per S3 convention.
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	escaped := strings.Join(segs, "/")

	if s.cfg.Endpoint != "" || s.cfg.ForcePathStyle {
		base := s.cfg.Endpoint
		if base == "" {
			base = "https://s3." + s.cfg.Region + ".amazonaws.com"
		}
		return strings.TrimRight(base, "/") + "/" + s.cfg.Bucket + "/" + escaped, nil
	}
	return "https://" + s.cfg.Bucket + ".s3." + s.cfg.Region + ".amazonaws.com/" + escaped, nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return strings.TrimSpace(string(b))
}
