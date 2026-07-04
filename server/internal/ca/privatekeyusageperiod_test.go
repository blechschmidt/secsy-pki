package ca

import (
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

func TestParseFlexibleDuration(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"365d", 365 * day, false},
		{"52w", 52 * 7 * day, false},
		{"1y", 365 * day, false},
		{"0.5y", time.Duration(0.5 * float64(365*day)), false},
		{"8760h", 8760 * time.Hour, false},
		{"24h30m", 24*time.Hour + 30*time.Minute, false},
		{"90D", 90 * day, false},
		{"", 0, true},
		{"365", 0, true}, // bare number, no unit
		{"abcd", 0, true},
		{"xy", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseFlexibleDuration(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseFlexibleDuration(%q) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFlexibleDuration(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseFlexibleDuration(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestPrivateKeyUsagePeriodConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     PrivateKeyUsagePeriodConfig
		wantErr bool
	}{
		{"empty block (no default, no override)", PrivateKeyUsagePeriodConfig{}, true},
		{"override-only", PrivateKeyUsagePeriodConfig{AllowOverride: true}, false},
		{"duration", PrivateKeyUsagePeriodConfig{Duration: "365d"}, false},
		{"fraction", PrivateKeyUsagePeriodConfig{Fraction: 0.5}, false},
		{"explicit not_after", PrivateKeyUsagePeriodConfig{NotAfter: "2030-01-01T00:00:00Z"}, false},
		{"explicit both", PrivateKeyUsagePeriodConfig{NotBefore: "2025-01-01T00:00:00Z", NotAfter: "2030-01-01T00:00:00Z"}, false},
		{"duration + fraction (two modes)", PrivateKeyUsagePeriodConfig{Duration: "1y", Fraction: 0.5}, true},
		{"duration + explicit (two modes)", PrivateKeyUsagePeriodConfig{Duration: "1y", NotAfter: "2030-01-01T00:00:00Z"}, true},
		{"bad duration", PrivateKeyUsagePeriodConfig{Duration: "nope"}, true},
		{"negative duration", PrivateKeyUsagePeriodConfig{Duration: "-5d"}, true},
		{"fraction > 1", PrivateKeyUsagePeriodConfig{Fraction: 1.5}, true},
		{"negative fraction", PrivateKeyUsagePeriodConfig{Fraction: -0.1}, true},
		{"bad explicit time", PrivateKeyUsagePeriodConfig{NotAfter: "not-a-time"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate("p")
			if tc.wantErr && err == nil {
				t.Error("expected a validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestResolveDefaultWindow(t *testing.T) {
	certNB := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	certNA := certNB.Add(365 * 24 * time.Hour)

	t.Run("duration inside validity", func(t *testing.T) {
		cfg := PrivateKeyUsagePeriodConfig{Duration: "90d"}
		p, present, err := cfg.resolveDefault(certNB, certNA)
		if err != nil || !present {
			t.Fatalf("resolveDefault = (%+v, %v, %v)", p, present, err)
		}
		if !p.NotBefore.Equal(certNB) {
			t.Errorf("notBefore = %v, want %v", p.NotBefore, certNB)
		}
		if want := certNB.Add(90 * 24 * time.Hour); !p.NotAfter.Equal(want) {
			t.Errorf("notAfter = %v, want %v", p.NotAfter, want)
		}
	})

	t.Run("duration exceeding validity is clamped to cert notAfter", func(t *testing.T) {
		cfg := PrivateKeyUsagePeriodConfig{Duration: "1000d"}
		p, present, err := cfg.resolveDefault(certNB, certNA)
		if err != nil || !present {
			t.Fatalf("resolveDefault = (%+v, %v, %v)", p, present, err)
		}
		if !p.NotAfter.Equal(certNA) {
			t.Errorf("notAfter = %v, want clamped to %v", p.NotAfter, certNA)
		}
	})

	t.Run("fraction of validity", func(t *testing.T) {
		cfg := PrivateKeyUsagePeriodConfig{Fraction: 0.5}
		p, present, err := cfg.resolveDefault(certNB, certNA)
		if err != nil || !present {
			t.Fatalf("resolveDefault = (%+v, %v, %v)", p, present, err)
		}
		if want := certNB.Add(182*24*time.Hour + 12*time.Hour); !p.NotAfter.Equal(want) {
			t.Errorf("notAfter = %v, want %v (half of a 365d validity)", p.NotAfter, want)
		}
	})

	t.Run("explicit bounds clamped to validity", func(t *testing.T) {
		cfg := PrivateKeyUsagePeriodConfig{
			NotBefore: "2020-01-01T00:00:00Z", // before cert validity
			NotAfter:  "2040-01-01T00:00:00Z", // after cert validity
		}
		p, present, err := cfg.resolveDefault(certNB, certNA)
		if err != nil || !present {
			t.Fatalf("resolveDefault = (%+v, %v, %v)", p, present, err)
		}
		if !p.NotBefore.Equal(certNB) {
			t.Errorf("notBefore = %v, want clamped up to %v", p.NotBefore, certNB)
		}
		if !p.NotAfter.Equal(certNA) {
			t.Errorf("notAfter = %v, want clamped down to %v", p.NotAfter, certNA)
		}
	})

	t.Run("override-only config yields no default", func(t *testing.T) {
		cfg := PrivateKeyUsagePeriodConfig{AllowOverride: true}
		_, present, err := cfg.resolveDefault(certNB, certNA)
		if err != nil {
			t.Fatalf("resolveDefault: %v", err)
		}
		if present {
			t.Error("override-only config should resolve to no default window")
		}
	})
}

func TestProfilePrivateKeyUsagePeriodGating(t *testing.T) {
	certNB := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	certNA := certNB.Add(365 * 24 * time.Hour)
	override := &models.PrivateKeyUsagePeriod{Duration: "30d"}

	t.Run("no profile config, no override → absent", func(t *testing.T) {
		p := Profile{Name: "p"}
		_, present, err := p.privateKeyUsagePeriod(nil, certNB, certNA)
		if err != nil || present {
			t.Errorf("= (present=%v, err=%v), want absent", present, err)
		}
	})

	t.Run("override on a profile with no PKUP config is rejected", func(t *testing.T) {
		p := Profile{Name: "p"}
		if _, _, err := p.privateKeyUsagePeriod(override, certNB, certNA); err == nil {
			t.Error("expected an error: a request cannot fabricate a PKUP the profile did not grant")
		}
	})

	t.Run("override on a profile that forbids overrides is rejected", func(t *testing.T) {
		p := Profile{Name: "p", PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{Duration: "180d"}}
		if _, _, err := p.privateKeyUsagePeriod(override, certNB, certNA); err == nil {
			t.Error("expected an error: profile does not set allow_override")
		}
	})

	t.Run("override honored when the profile permits it", func(t *testing.T) {
		p := Profile{Name: "p", PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{Duration: "180d", AllowOverride: true}}
		got, present, err := p.privateKeyUsagePeriod(override, certNB, certNA)
		if err != nil || !present {
			t.Fatalf("= (%+v, %v, %v)", got, present, err)
		}
		if want := certNB.Add(30 * 24 * time.Hour); !got.NotAfter.Equal(want) {
			t.Errorf("override notAfter = %v, want %v (30d, not the 180d default)", got.NotAfter, want)
		}
	})

	t.Run("empty override falls back to the profile default", func(t *testing.T) {
		p := Profile{Name: "p", PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{Duration: "180d", AllowOverride: true}}
		got, present, err := p.privateKeyUsagePeriod(&models.PrivateKeyUsagePeriod{}, certNB, certNA)
		if err != nil || !present {
			t.Fatalf("= (%+v, %v, %v)", got, present, err)
		}
		if want := certNB.Add(180 * 24 * time.Hour); !got.NotAfter.Equal(want) {
			t.Errorf("notAfter = %v, want the 180d default %v", got.NotAfter, want)
		}
	})
}

func TestApplyPrivateKeyUsagePeriod(t *testing.T) {
	nb := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	base := pki.LeafCertRequest{NotBefore: nb, NotAfter: nb.Add(365 * 24 * time.Hour)}

	t.Run("no config → unchanged", func(t *testing.T) {
		out, err := applyPrivateKeyUsagePeriod(base, Profile{Name: "p"}, nil)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if len(out.ExtraExtensions) != 0 {
			t.Errorf("expected no extension, got %d", len(out.ExtraExtensions))
		}
	})

	t.Run("stamps a decodable non-critical extension", func(t *testing.T) {
		p := Profile{Name: "p", PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{Duration: "90d"}}
		out, err := applyPrivateKeyUsagePeriod(base, p, nil)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		var found bool
		for _, ext := range out.ExtraExtensions {
			if !ext.Id.Equal(pki.OIDPrivateKeyUsagePeriod) {
				continue
			}
			found = true
			if ext.Critical {
				t.Error("privateKeyUsagePeriod must be non-critical")
			}
			pkup, perr := pki.ParsePrivateKeyUsagePeriod(ext.Value)
			if perr != nil {
				t.Fatalf("Parse: %v", perr)
			}
			if !pkup.NotBefore.Equal(nb) {
				t.Errorf("notBefore = %v, want %v", pkup.NotBefore, nb)
			}
			if want := nb.Add(90 * 24 * time.Hour); !pkup.NotAfter.Equal(want) {
				t.Errorf("notAfter = %v, want %v", pkup.NotAfter, want)
			}
		}
		if !found {
			t.Fatal("privateKeyUsagePeriod extension not appended")
		}
	})

	t.Run("does not mutate the caller's extension slice", func(t *testing.T) {
		p := Profile{Name: "p", PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{Duration: "90d"}}
		withExt := base
		withExt.ExtraExtensions = make([]pkix.Extension, 0, 1)
		_, err := applyPrivateKeyUsagePeriod(withExt, p, nil)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if len(withExt.ExtraExtensions) != 0 {
			t.Error("apply mutated the caller's ExtraExtensions slice")
		}
	})
}
