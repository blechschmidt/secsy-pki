package hsm

// Deciding whether this process should multiplex the YubiHSM itself, and doing
// it.
//
// internal/yubihsm.StartEmbedded is the mechanism: an in-process
// yubihsm-connector that holds the USB device and relays for Yubico's PKCS#11
// module, so one process — and therefore one container — can both sign and
// drain the device audit log. What belongs here is the policy: *when* a
// deployment needs it, which address it serves, and how a process that finds
// one already running joins it instead of competing.
//
// The policy lives next to EffectiveConnectorURL on purpose. The decision is a
// function of the same resolved connector URL the signing path uses, and the
// two must agree: a process that decided "no relay needed" while the module
// went looking for one, or the reverse, is exactly the split-brain the audit
// subsystem cannot tolerate. Three callers consult it — the server, secsy-ca
// and `secsy-ca doctor` — and all three have to reach the same verdict from the
// same configuration, including the doctor, which runs in a process where no
// relay is up and so can only reason from the config.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// EmbeddedConnectorOptions is the configuration the decision depends on.
type EmbeddedConnectorOptions struct {
	// Enabled is yubihsm.embedded_connector.enabled: nil means "decide", which
	// is what an operator who has configured nothing gets.
	Enabled *bool
	// Listen overrides the address the relay serves. Empty derives one.
	Listen string
	// Device pins which attached YubiHSM the relay holds, as a yhusb:// URL.
	// Empty means the single attached device.
	Device string
	// ConnectorURL is the configured yubihsm.connector_url, verbatim. It is not
	// pre-resolved because the resolution itself depends on the decision: a
	// relay that is going to run is the endpoint the PKCS#11 configuration will
	// name, so reading that configuration back would be circular.
	ConnectorURL string
	// PKCS11Module is the YubiHSM PKCS#11 module a signing role drives the
	// device through, or "" when none does (config.SigningPKCS11Module).
	PKCS11Module string
}

// EmbeddedConnectorPlan is the verdict.
type EmbeddedConnectorPlan struct {
	// Start says whether this process should run the relay.
	Start bool
	// Listen is the address to serve on when Start.
	Listen string
	// DeviceURL is the yhusb:// device to hold when Start.
	DeviceURL string
	// URL is the connector URL clients should use when Start.
	URL string
	// Reason explains the verdict in one line, for the startup log and for
	// `secsy-ca doctor`.
	Reason string
	// Err marks a configuration that asks for the relay and cannot have it.
	// It is a field rather than a second return value because every caller
	// wants the explanation alongside the verdict, and because a bad
	// configuration here must be loud: silently not starting the relay is how a
	// force-audited device ends up wedged.
	Err error
}

// PlanEmbeddedConnector decides whether this process multiplexes the device.
//
// The rules, in order:
//
//   - An explicit `false` is final. An operator who turned the relay off is
//     running Yubico's connector, or has no contention to resolve, and must not
//     be second-guessed into binding a port.
//   - On direct USB, an explicit `true` starts it; an unset value starts it iff
//     a YubiHSM PKCS#11 module signs — i.e. exactly the configuration
//     hsmaudit.DrainContention would otherwise refuse. The default is to make
//     that deployment work rather than to reject it.
//   - On a loopback http:// URL, only an explicit `true` starts it, serving
//     that address. Unset means the historical reading of such a URL: a
//     yubihsm-connector daemon on this host, which this process must not try to
//     replace.
//   - On any other connector URL the device is already shareable and already
//     somebody else's to hold, so the relay is neither needed nor possible. A
//     deployment that asked for it there is misconfigured and told so.
func PlanEmbeddedConnector(o EmbeddedConnectorOptions) EmbeddedConnectorPlan {
	configured := strings.TrimSpace(o.ConnectorURL)
	if configured == "" {
		// The same fallback chain the module uses, so a deployment that
		// configured only YUBIHSM_PKCS11_CONF is read the same way here.
		configured = connectorArg(Config{})
	}
	if o.Enabled != nil && !*o.Enabled {
		return EmbeddedConnectorPlan{Reason: "yubihsm.embedded_connector.enabled is false"}
	}
	explicit := o.Enabled != nil && *o.Enabled

	deviceURL := strings.TrimSpace(o.Device)
	if deviceURL == "" {
		deviceURL = "yhusb://"
	}
	if !yubihsm.IsDirectUSB(deviceURL) {
		return EmbeddedConnectorPlan{Err: fmt.Errorf(
			"yubihsm.embedded_connector.device is %q: the relay holds a USB device, so it must be a yhusb:// URL",
			o.Device)}
	}

	switch {
	case yubihsm.IsDirectUSB(configured):
		listen := strings.TrimSpace(o.Listen)
		if listen == "" {
			listen = yubihsm.DefaultEmbeddedListen
		}
		plan := EmbeddedConnectorPlan{
			Start:     true,
			Listen:    listen,
			DeviceURL: deviceURL,
			URL:       "http://" + listen,
		}
		switch {
		case explicit:
			plan.Reason = fmt.Sprintf("yubihsm.embedded_connector.enabled is true: this process holds %s and relays on %s",
				deviceURL, plan.URL)
		case o.PKCS11Module != "":
			plan.Reason = fmt.Sprintf("the device is on %s and %s signs through it, so this process multiplexes it "+
				"on %s — one container, no yubihsm-connector daemon", deviceURL, o.PKCS11Module, plan.URL)
		default:
			// Nothing competes for the device: the native driver has it to
			// itself, which is already a working deployment. Binding a port to
			// relay for nobody would only add a failure mode.
			return EmbeddedConnectorPlan{Reason: fmt.Sprintf(
				"the device is on %s and no PKCS#11 signing path competes for it, so no relay is needed", deviceURL)}
		}
		return plan

	case yubihsm.IsLocalConnectorURL(configured):
		if !explicit {
			return EmbeddedConnectorPlan{Reason: fmt.Sprintf(
				"yubihsm.connector_url is %s, which is read as a yubihsm-connector already running here; "+
					"set yubihsm.embedded_connector.enabled to serve that address from this process instead",
				configured)}
		}
		host, err := yubihsm.ConnectorHostPort(configured)
		if err != nil {
			return EmbeddedConnectorPlan{Err: err}
		}
		listen := strings.TrimSpace(o.Listen)
		if listen == "" {
			listen = host
		}
		return EmbeddedConnectorPlan{
			Start:     true,
			Listen:    listen,
			DeviceURL: deviceURL,
			URL:       configured,
			Reason: fmt.Sprintf("yubihsm.embedded_connector.enabled is true: this process holds %s and serves "+
				"the configured %s itself", deviceURL, configured),
		}

	case explicit:
		return EmbeddedConnectorPlan{Err: fmt.Errorf(
			"yubihsm.embedded_connector.enabled is true but yubihsm.connector_url is %s, which names another "+
				"host: the relay can only serve a local address, because what it multiplexes is a USB device "+
				"attached to this one. Either point connector_url at a loopback address this process should "+
				"serve (e.g. http://127.0.0.1:12345), leave it unset for direct USB, or turn the relay off and "+
				"let that connector hold the device", configured)}

	default:
		return EmbeddedConnectorPlan{Reason: fmt.Sprintf(
			"the device is reached over %s, which already multiplexes it", configured)}
	}
}

// StartEmbeddedConnector runs the planned relay and points the PKCS#11 module
// at it.
//
// A relay already bound to the address is not a failure: in a single-container
// deployment that is this program's own server process, and the right outcome
// for an `secsy-ca` invocation is to use it. It returns (nil, nil) in that
// case, having still pointed the module at the URL — the device is multiplexed
// either way, which is all the caller needed.
//
// The caller must Close a non-nil return.
func StartEmbeddedConnector(ctx context.Context, plan EmbeddedConnectorPlan, logger *log.Logger) (*yubihsm.Embedded, error) {
	if plan.Err != nil {
		return nil, plan.Err
	}
	if !plan.Start {
		return nil, nil
	}
	if logger == nil {
		logger = log.Default()
	}
	e, err := yubihsm.StartEmbedded(ctx, yubihsm.EmbeddedConfig{
		DeviceURL: plan.DeviceURL,
		Listen:    plan.Listen,
		Logger:    logger,
	})
	switch {
	case err == nil:
		if cerr := PointPKCS11At(e.URL(), logger); cerr != nil {
			_ = e.Close()
			return nil, cerr
		}
		return e, nil
	case errors.Is(err, yubihsm.ErrEmbeddedAddrInUse):
		logger.Printf("A YubiHSM connector is already serving %s, so this process will use it rather than "+
			"claiming the device: %v", plan.URL, err)
		if cerr := PointPKCS11At(plan.URL, logger); cerr != nil {
			return nil, cerr
		}
		return nil, nil
	default:
		return nil, err
	}
}

// PointPKCS11At makes Yubico's PKCS#11 module address the device at connectorURL.
//
// The module reads one line of configuration from the file named by
// YUBIHSM_PKCS11_CONF, at C_Initialize, so this has to happen before any key
// provider is built. It writes a fresh file and overrides the variable even
// when one is already set, which is the whole point: an image or a host that
// ships /etc/yubihsm_pkcs11.conf saying `connector = yhusb://` would otherwise
// send the module straight at the USB interface this process is holding, and
// the deployment would be back to the contention the relay exists to remove.
//
// The written file goes next to the working directory when that is writable and
// falls back to the temporary directory, because a container that mounts its
// configuration read-only still has to be able to run.
func PointPKCS11At(connectorURL string, logger *log.Logger) error {
	if logger == nil {
		logger = log.Default()
	}
	content := []byte("connector = " + connectorURL + "\n")
	var errs []error
	for _, dir := range []string{".", os.TempDir()} {
		path := filepath.Join(dir, "yubihsm_pkcs11.conf")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			errs = append(errs, err)
			continue
		}
		abs, aerr := filepath.Abs(path)
		if aerr != nil {
			abs = path
		}
		if err := os.Setenv("YUBIHSM_PKCS11_CONF", abs); err != nil {
			return fmt.Errorf("setting YUBIHSM_PKCS11_CONF: %w", err)
		}
		logger.Printf("YubiHSM PKCS#11 module pointed at %s (via %s)", connectorURL, abs)
		return nil
	}
	return fmt.Errorf("writing a yubihsm_pkcs11.conf naming %s: %w", connectorURL, errors.Join(errs...))
}
