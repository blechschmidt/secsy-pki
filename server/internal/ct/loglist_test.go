package ct

import "testing"

// A trimmed but structurally faithful Google/Chrome CT log-list v3 document:
// two operators, one with a classic RFC 6962 log and one with both a classic and
// a static/tiled log. Trailing slashes on URLs mirror the real list so the
// normalization is exercised.
const sampleLogList = `{
  "operators": [
    {
      "name": "Google",
      "email": ["ct@google.example"],
      "logs": [
        { "description": "Google 'Argon2025'", "log_id": "AAAA", "url": "https://ct.googleapis.com/logs/argon2025/" }
      ]
    },
    {
      "name": "Cloudflare",
      "logs": [
        { "description": "Cloudflare 'Nimbus2025'", "log_id": "BBBB", "url": "https://ct.cloudflare.com/logs/nimbus2025" }
      ],
      "tiled_logs": [
        { "description": "Cloudflare tiled", "log_id": "CCCC", "submission_url": "https://ct.cloudflare.com/tiled/", "monitoring_url": "https://ct.cloudflare.com/tiled/" }
      ]
    }
  ]
}`

func TestLoadOperatorMap(t *testing.T) {
	m, err := LoadOperatorMap([]byte(sampleLogList))
	if err != nil {
		t.Fatalf("LoadOperatorMap: %v", err)
	}
	cases := map[string]string{
		"https://ct.googleapis.com/logs/argon2025":  "Google",     // trailing slash stripped
		"https://ct.cloudflare.com/logs/nimbus2025": "Cloudflare", // no trailing slash
		"https://ct.cloudflare.com/tiled":           "Cloudflare", // tiled submission/monitoring url
	}
	for url, want := range cases {
		if got := m[url]; got != want {
			t.Errorf("operator for %q = %q, want %q", url, got, want)
		}
	}
	if len(m) != 3 {
		t.Errorf("map has %d entries, want 3: %v", len(m), m)
	}
}

func TestLoadOperatorMapErrors(t *testing.T) {
	if _, err := LoadOperatorMap([]byte("not json")); err == nil {
		t.Error("expected an error for malformed JSON")
	}
	// Well-formed but no usable entries → loud error rather than an empty map.
	if _, err := LoadOperatorMap([]byte(`{"operators":[{"name":"","logs":[{"url":""}]}]}`)); err == nil {
		t.Error("expected an error for a log list with no operator/url pairs")
	}
}

func TestApplyOperators(t *testing.T) {
	m, err := LoadOperatorMap([]byte(sampleLogList))
	if err != nil {
		t.Fatalf("LoadOperatorMap: %v", err)
	}
	logs := []LogConfig{
		{Name: "argon", URL: "https://ct.googleapis.com/logs/argon2025"},               // filled from list
		{Name: "nimbus", URL: "https://ct.cloudflare.com/logs/nimbus2025/"},            // filled (trailing slash on config side)
		{Name: "private", URL: "https://ct.internal.example/log", Operator: "InHouse"}, // explicit operator preserved
		{Name: "unknown", URL: "https://ct.unknown.example/log"},                       // absent from list — left empty
	}
	filled := ApplyOperators(logs, m)
	if filled != 2 {
		t.Errorf("ApplyOperators filled %d, want 2", filled)
	}
	want := []string{"Google", "Cloudflare", "InHouse", ""}
	for i, w := range want {
		if logs[i].Operator != w {
			t.Errorf("logs[%d].Operator = %q, want %q", i, logs[i].Operator, w)
		}
	}
}
