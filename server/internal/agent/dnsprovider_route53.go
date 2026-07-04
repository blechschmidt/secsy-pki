package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// route53API is the minimal Route 53 surface the provider needs, so tests can
// substitute a fake without touching AWS.
type route53API interface {
	ChangeResourceRecordSets(ctx context.Context, in *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	ListHostedZonesByName(ctx context.Context, in *route53.ListHostedZonesByNameInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error)
}

// route53Provider answers dns-01 challenges by upserting/deleting the
// _acme-challenge TXT record in an AWS Route 53 hosted zone. It reuses the AWS
// SDK already vendored for the Cloud KMS key-provider backend.
type route53Provider struct {
	api          route53API
	hostedZoneID string // explicit zone id, or "" to discover
	ttl          int64
}

// newRoute53Provider builds the provider, resolving AWS configuration through
// the standard SDK chain with optional static-credential and region overrides.
func newRoute53Provider(ctx context.Context, cfg *Route53Config) (*route53Provider, error) {
	if cfg == nil {
		cfg = &Route53Config{TTL: defaultRoute53TTL}
	}
	var optFns []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		optFns = append(optFns, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.AccessKeyID != "" || cfg.SecretAccessKey != "" {
		optFns = append(optFns, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken)))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("route53: loading AWS config: %w", err)
	}
	// Route 53 is a global service but the SDK still requires a region.
	if awsCfg.Region == "" {
		awsCfg.Region = "us-east-1"
	}
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = defaultRoute53TTL
	}
	return &route53Provider{
		api:          route53.NewFromConfig(awsCfg),
		hostedZoneID: strings.TrimSpace(cfg.HostedZoneID),
		ttl:          ttl,
	}, nil
}

// Present upserts the challenge TXT record.
func (p *route53Provider) Present(ctx context.Context, fqdn, value string) error {
	return p.change(ctx, types.ChangeActionUpsert, fqdn, value)
}

// CleanUp deletes the challenge TXT record.
func (p *route53Provider) CleanUp(ctx context.Context, fqdn, value string) error {
	return p.change(ctx, types.ChangeActionDelete, fqdn, value)
}

// change applies one record-set change (UPSERT or DELETE) to the resolved zone.
func (p *route53Provider) change(ctx context.Context, action types.ChangeAction, fqdn, value string) error {
	zoneID, err := p.resolveZoneID(ctx, fqdn)
	if err != nil {
		return err
	}
	rrset := &types.ResourceRecordSet{
		Name:            aws.String(ensureTrailingDot(fqdn)),
		Type:            types.RRTypeTxt,
		TTL:             aws.Int64(p.ttl),
		ResourceRecords: []types.ResourceRecord{{Value: aws.String(route53TXTValue(value))}},
	}
	_, err = p.api.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{{Action: action, ResourceRecordSet: rrset}},
		},
	})
	if err != nil {
		return fmt.Errorf("route53: %s TXT %s: %w", strings.ToLower(string(action)), fqdn, err)
	}
	return nil
}

// resolveZoneID returns the configured hosted-zone id, or discovers the most
// specific public zone that encloses fqdn.
func (p *route53Provider) resolveZoneID(ctx context.Context, fqdn string) (string, error) {
	if p.hostedZoneID != "" {
		return p.hostedZoneID, nil
	}
	labels := dnsLabels(fqdn)
	for i := 1; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".") + "."
		id, err := p.lookupZoneID(ctx, candidate)
		if err != nil {
			return "", err
		}
		if id != "" {
			return id, nil
		}
	}
	return "", fmt.Errorf("route53: no public hosted zone found for %s (set acme.dns01.route53.hosted_zone_id)", fqdn)
}

// lookupZoneID returns the id of the public hosted zone whose name exactly
// matches candidate, or "" when none does.
func (p *route53Provider) lookupZoneID(ctx context.Context, candidate string) (string, error) {
	out, err := p.api.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{DNSName: aws.String(candidate)})
	if err != nil {
		return "", fmt.Errorf("route53: listing hosted zones: %w", err)
	}
	want := canonicalDNSName(candidate)
	for _, z := range out.HostedZones {
		if z.Name == nil || z.Id == nil {
			continue
		}
		if z.Config != nil && z.Config.PrivateZone {
			continue
		}
		if canonicalDNSName(*z.Name) == want {
			return strings.TrimPrefix(*z.Id, "/hostedzone/"), nil
		}
	}
	return "", nil
}

// route53TXTValue renders a TXT record value the way the Route 53 API expects
// it: the character-string wrapped in double quotes.
func route53TXTValue(value string) string {
	return `"` + value + `"`
}
