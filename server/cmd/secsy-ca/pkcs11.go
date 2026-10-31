package main

// `secsy-ca pkcs11` — the raw Cryptoki view of the configured token (Task 218),
// and the CLI counterpart of the console's PKCS#11 page.
//
// `inventory` answers the PKI's question: which keys do we hold, and is any of
// them extractable. This answers the token's: what objects exist at all, what
// does each attribute actually say, which slot is this, what does the module
// claim to support. The two differ exactly when it matters — an object with no
// label, a duplicate label, a certificate or data object the inventory does not
// model, a mechanism the firmware does not really offer.
//
// It reads only. There is no create/modify/destroy path here, and private key
// material is never requested (see the policy note in internal/pki/pkcs11attrs.go).

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// cmdPKCS11 dispatches the pkcs11 subcommands.
func cmdPKCS11(provider keyprovider.Provider, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secsy-ca pkcs11 <module|objects|mechanisms> [flags]")
	}
	ins, ok := provider.(keyprovider.PKCS11Inspector)
	if !ok {
		return fmt.Errorf("the configured key provider (%s) has no PKCS#11 view", provider.Name())
	}
	switch args[0] {
	case "module":
		return cmdPKCS11Module(ins, args[1:])
	case "objects":
		return cmdPKCS11Objects(ins, args[1:])
	case "mechanisms":
		return cmdPKCS11Mechanisms(ins, args[1:])
	default:
		return fmt.Errorf("unknown pkcs11 subcommand %q (want module, objects or mechanisms)", args[0])
	}
}

// cmdPKCS11Module prints C_GetInfo, every slot, and the token in each.
func cmdPKCS11Module(ins keyprovider.PKCS11Inspector, args []string) error {
	fs := flag.NewFlagSet("pkcs11 module", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the raw view as JSON")
	mechanisms := fs.Bool("mechanisms", false, "include each slot's mechanism list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	views, err := ins.InspectPKCS11Module(context.Background(), pki.InspectOptions{SkipMechanisms: !*mechanisms})
	if err != nil {
		return fmt.Errorf("reading the PKCS#11 module view: %w", err)
	}
	if *asJSON {
		return emitJSON(views)
	}
	for _, v := range views {
		printTokenHeader(v)
		if v.Module == nil {
			continue
		}
		printModule(v.Module, *mechanisms)
	}
	return nil
}

// cmdPKCS11Mechanisms prints the mechanism table of every slot: what the module
// says it can do, with the key-size range and flags for each mechanism.
func cmdPKCS11Mechanisms(ins keyprovider.PKCS11Inspector, args []string) error {
	fs := flag.NewFlagSet("pkcs11 mechanisms", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the raw view as JSON")
	filter := fs.String("filter", "", "only mechanisms whose CKM_ name contains this substring (case-insensitive)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	views, err := ins.InspectPKCS11Module(context.Background(), pki.InspectOptions{})
	if err != nil {
		return fmt.Errorf("reading the PKCS#11 module view: %w", err)
	}
	if *asJSON {
		return emitJSON(views)
	}
	for _, v := range views {
		printTokenHeader(v)
		if v.Module == nil {
			continue
		}
		for _, s := range v.Module.Slots {
			if len(s.Mechanisms) == 0 {
				continue
			}
			fmt.Printf("\nslot %d (%s)\n", s.SlotID, s.Description)
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "MECHANISM\tTYPE\tMIN KEY\tMAX KEY\tFLAGS")
			var shown int
			for _, m := range s.Mechanisms {
				if *filter != "" && !strings.Contains(strings.ToLower(m.Name), strings.ToLower(*filter)) {
					continue
				}
				shown++
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", m.Name, m.Hex, m.MinKeySize, m.MaxKeySize,
					strings.Join(m.Flags.Names, " "))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Printf("%d of %d mechanism(s).\n", shown, len(s.Mechanisms))
		}
	}
	return nil
}

// cmdPKCS11Objects enumerates the token's objects and prints each object's
// attribute table.
func cmdPKCS11Objects(ins keyprovider.PKCS11Inspector, args []string) error {
	fs := flag.NewFlagSet("pkcs11 objects", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the raw view as JSON")
	brief := fs.Bool("brief", false, "one line per object instead of the full attribute table")
	all := fs.Bool("all", false, "ask every object for every catalogued attribute, including the ones it does not have")
	label := fs.String("label", "", "only objects whose CKA_LABEL equals this value")
	class := fs.String("class", "", "only objects of this class (e.g. private-key, public-key, certificate, data, secret-key)")
	maxObjects := fs.Int("max-objects", 0, "cap the number of objects enumerated (0 = the default cap)")
	maxValue := fs.Int("max-value-bytes", 0, "cap the hex rendering of one attribute value (0 = the default cap)")
	raw := fs.Bool("raw", false, "print the hex bytes of every attribute value, not only the decoding")
	if err := fs.Parse(args); err != nil {
		return err
	}
	wantClass, err := parseObjectClass(*class)
	if err != nil {
		return err
	}

	views, err := ins.InspectPKCS11(context.Background(), pki.InspectOptions{
		AllAttributes:  *all,
		MaxObjects:     *maxObjects,
		MaxValueBytes:  *maxValue,
		SkipMechanisms: true,
	})
	if err != nil {
		return fmt.Errorf("enumerating PKCS#11 objects: %w", err)
	}

	// Filtering happens after enumeration on purpose: an object is selected by
	// attributes that have to be read first, and a token with few objects is
	// the normal case. The JSON form is filtered the same way, so a scripted
	// consumer sees exactly the rows the table shows.
	enumerated := make([]int, len(views))
	for i := range views {
		if views[i].Objects == nil {
			continue
		}
		enumerated[i] = len(views[i].Objects.Objects)
		views[i].Objects.Objects = filterObjects(views[i].Objects.Objects, *label, wantClass)
	}
	if *asJSON {
		return emitJSON(views)
	}

	for i, v := range views {
		printTokenHeader(v)
		if v.Objects == nil {
			continue
		}
		set := v.Objects
		// "showing N of M": the class counts below describe everything that was
		// enumerated, so saying only the filtered count would make them look
		// wrong.
		fmt.Printf("token %q (serial %s), slot %d — showing %d of %d object(s)%s\n",
			set.TokenLabel, set.TokenSerial, set.SlotID, len(set.Objects), enumerated[i], truncatedNote(set.Truncated))
		if len(set.Counts) > 0 {
			fmt.Printf("by class: %s\n", formatCounts(set.Counts))
		}
		if *brief {
			if err := printObjectsBrief(set.Objects); err != nil {
				return err
			}
			continue
		}
		for _, o := range set.Objects {
			if err := printObject(o, *raw); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- rendering --------------------------------------------------------------

// printTokenHeader names the member token in a high-availability set, where the
// same key labels appear on every replica and only the member name tells them
// apart. A single-token deployment prints nothing.
func printTokenHeader(v keyprovider.TokenView) {
	if v.Token != "" {
		health := ""
		if v.Healthy != nil && !*v.Healthy {
			health = " [UNHEALTHY — out of rotation]"
		}
		fmt.Printf("\n=== token %s%s ===\n", v.Token, health)
	}
	if v.Error != "" {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", v.Error)
	}
}

func printModule(m *pki.ModuleInfo, withMechanisms bool) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "module path\t%s\n", m.ModulePath)
	fmt.Fprintf(tw, "cryptoki version\t%s\n", m.CryptokiVersion)
	fmt.Fprintf(tw, "manufacturer\t%s\n", m.ManufacturerID)
	fmt.Fprintf(tw, "library\t%s %s\n", m.LibraryDescription, m.LibraryVersion)
	fmt.Fprintf(tw, "flags\t%s %s\n", m.Flags.Hex, strings.Join(m.Flags.Names, " "))
	if err := tw.Flush(); err != nil {
		return
	}

	for _, s := range m.Slots {
		marker := ""
		if s.Selected {
			marker = "  <- this deployment's token"
		}
		fmt.Printf("\nslot %d%s\n", s.SlotID, marker)
		st := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintf(st, "  description\t%s\n", s.Description)
		fmt.Fprintf(st, "  manufacturer\t%s\n", s.ManufacturerID)
		fmt.Fprintf(st, "  hardware/firmware\t%s / %s\n", s.HardwareVersion, s.FirmwareVersion)
		fmt.Fprintf(st, "  flags\t%s %s\n", s.Flags.Hex, strings.Join(s.Flags.Names, " "))
		fmt.Fprintf(st, "  token present\t%t\n", s.TokenPresent)
		if t := s.Token; t != nil {
			fmt.Fprintf(st, "  token label\t%s\n", t.Label)
			fmt.Fprintf(st, "  token model\t%s\n", t.Model)
			fmt.Fprintf(st, "  token manufacturer\t%s\n", t.ManufacturerID)
			fmt.Fprintf(st, "  token serial\t%s\n", t.SerialNumber)
			fmt.Fprintf(st, "  token flags\t%s %s\n", t.Flags.Hex, strings.Join(t.Flags.Names, " "))
			fmt.Fprintf(st, "  sessions\t%s of %s (rw %s of %s)\n", t.SessionCount, t.MaxSessionCount, t.RwSessionCount, t.MaxRwSessionCount)
			fmt.Fprintf(st, "  pin length\t%s..%s\n", t.MinPinLen, t.MaxPinLen)
			fmt.Fprintf(st, "  public memory\t%s free of %s\n", t.FreePublicMemory, t.TotalPublicMemory)
			fmt.Fprintf(st, "  private memory\t%s free of %s\n", t.FreePrivateMemory, t.TotalPrivateMemory)
			fmt.Fprintf(st, "  token hw/fw\t%s / %s\n", t.HardwareVersion, t.FirmwareVersion)
			if t.UTCTime != "" {
				fmt.Fprintf(st, "  token clock\t%s\n", t.UTCTime)
			}
		}
		if s.Error != "" {
			fmt.Fprintf(st, "  error\t%s\n", s.Error)
		}
		if err := st.Flush(); err != nil {
			return
		}
		if withMechanisms && len(s.Mechanisms) > 0 {
			names := make([]string, 0, len(s.Mechanisms))
			for _, mech := range s.Mechanisms {
				names = append(names, mech.Name)
			}
			fmt.Printf("  mechanisms (%d)\t%s\n", len(names), strings.Join(names, ", "))
		}
	}
}

func printObjectsBrief(objs []pki.Object) error {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HANDLE\tCLASS\tLABEL\tCKA_ID\tTYPE\tATTRS")
	for _, o := range objs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", o.HandleHex, o.ClassName, quoteEmpty(o.Label), quoteEmpty(o.ID), o.KeyType, len(o.Attributes))
	}
	return tw.Flush()
}

// printObject prints one object's full attribute table — the point of the
// command. Every row says what the token answered, or why it did not.
func printObject(o pki.Object, raw bool) error {
	fmt.Printf("\n--- object %s: %s %s\n", o.HandleHex, o.ClassName, quoteEmpty(o.Label))
	if o.Size != "" {
		fmt.Printf("    C_GetObjectSize: %s bytes\n", o.Size)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  ATTRIBUTE\tTYPE\tKIND\tLEN\tVALUE")
	for _, a := range o.Attributes {
		value := a.Value
		switch a.Status {
		case pki.AttrStatusUnavailable, pki.AttrStatusWithheld, pki.AttrStatusNotRead:
			value = "(" + a.Status + ": " + a.Reason + ")"
		default:
			if value == "" && a.Raw != "" {
				value = "0x" + a.Raw
			}
			if raw && a.Raw != "" && !strings.HasPrefix(value, "0x"+a.Raw) {
				value += "  [0x" + a.Raw + truncMark(a.RawTruncated) + "]"
			}
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%s\n", a.Name, a.TypeHex, a.Kind, a.Length, value)
	}
	return tw.Flush()
}

func truncMark(truncated bool) string {
	if truncated {
		return "…"
	}
	return ""
}

func truncatedNote(truncated bool) string {
	if truncated {
		return " (TRUNCATED: the token holds more; raise -max-objects)"
	}
	return ""
}

func quoteEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func formatCounts(counts map[string]int) string {
	parts := make([]string, 0, len(counts))
	for _, name := range sortedKeys(counts) {
		parts = append(parts, fmt.Sprintf("%s=%d", name, counts[name]))
	}
	return strings.Join(parts, " ")
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// parseObjectClass maps the -class flag to a CKA_CLASS name. The accepted
// spellings are the CKO_ names with or without the prefix, hyphenated or not,
// so both `-class private-key` and `-class CKO_PRIVATE_KEY` work.
func parseObjectClass(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	norm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", "_"))
	if !strings.HasPrefix(norm, "CKO_") {
		norm = "CKO_" + norm
	}
	switch norm {
	case "CKO_DATA", "CKO_CERTIFICATE", "CKO_PUBLIC_KEY", "CKO_PRIVATE_KEY", "CKO_SECRET_KEY",
		"CKO_HW_FEATURE", "CKO_DOMAIN_PARAMETERS", "CKO_MECHANISM", "CKO_OTP_KEY":
		return norm, nil
	}
	return "", fmt.Errorf("unknown object class %q (want data, certificate, public-key, private-key, secret-key, hw-feature, domain-parameters, mechanism or otp-key)", s)
}

func filterObjects(objs []pki.Object, label, class string) []pki.Object {
	if label == "" && class == "" {
		return objs
	}
	out := make([]pki.Object, 0, len(objs))
	for _, o := range objs {
		if label != "" && o.Label != label {
			continue
		}
		if class != "" && o.ClassName != class {
			continue
		}
		out = append(out, o)
	}
	return out
}
