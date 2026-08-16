package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// inventoryItem is the stable JSON shape of one inventoried key: the provider's
// key descriptor plus the operational role resolved from the CA registry.
type inventoryItem struct {
	keyprovider.KeyDescriptor
	Role string `json:"role"`
}

// cmdInventory lists the keys held by the configured key provider and
// cross-references them with the CAs recorded in the database. It surfaces the
// key non-extractability invariant directly from the token: any key reported as
// extractable is flagged, since a CA/KEK private key must never be exportable.
func cmdInventory(db *database.DB, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	strict := fs.Bool("strict", false, "exit non-zero if any key is extractable or unaccounted for")
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}

	lister, ok := provider.(keyprovider.KeyLister)
	if !ok {
		return fmt.Errorf("the configured key provider (%s) does not support key inventory", provider.Name())
	}

	keys, err := lister.ListKeys(context.Background())
	if err != nil {
		return fmt.Errorf("listing keys: %w", err)
	}

	// Map each provider key label to the CA(s) that reference it, so the
	// inventory shows the operational role of every key.
	cas, err := db.ListCAs()
	if err != nil {
		return fmt.Errorf("listing CAs: %w", err)
	}
	caByLabel := map[string]string{}
	for _, c := range cas {
		label := pki.ExtractKeyLabel(c.PKCS11URI)
		if label == "" {
			label = c.Label
		}
		caByLabel[label] = c.Label
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i].Label < keys[j].Label })

	// Annotate every key with its role and count extractable keys once, shared
	// by both output modes.
	items := make([]inventoryItem, 0, len(keys))
	var extractable int
	for _, k := range keys {
		role := caByLabel[k.Label]
		if role == "" {
			role = "(not bound to a CA)"
		}
		if k.Extractable {
			extractable++
		}
		items = append(items, inventoryItem{KeyDescriptor: k, Role: role})
	}

	if asJSON {
		if err := cliout.Emit(struct {
			Provider         string          `json:"provider"`
			Keys             []inventoryItem `json:"keys"`
			ExtractableCount int             `json:"extractable_count"`
		}{Provider: provider.Name(), Keys: items, ExtractableCount: extractable}); err != nil {
			return err
		}
		if *strict && extractable > 0 {
			return fmt.Errorf("inventory: %d extractable key(s) present", extractable)
		}
		return nil
	}

	if len(items) == 0 {
		fmt.Println("No keys found on the key provider.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LABEL\tKEY TYPE\tEXTRACTABLE\tSENSITIVE\tCA / ROLE")
	for _, k := range items {
		ext := "no"
		if k.Extractable {
			ext = "YES ⚠"
		}
		sens := "no"
		if k.Sensitive {
			sens = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", k.Label, k.KeyType, ext, sens, k.Role)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Printf("\n%d key(s) on provider %q.\n", len(items), provider.Name())
	if extractable > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %d key(s) are marked extractable — a CA/KEK private key must be non-extractable.\n", extractable)
	}
	if provider.Name() == string(keyprovider.ProviderSoftware) {
		fmt.Fprintln(os.Stderr, "NOTE: the software provider stores keys as on-disk files; use an HSM (pkcs11) for production CA/KEK keys.")
	}

	if *strict && extractable > 0 {
		return fmt.Errorf("inventory: %d extractable key(s) present", extractable)
	}
	return nil
}
