package ct

import (
	"encoding/json"
	"fmt"
	"strings"
)

// logList mirrors the subset of the Google/Chrome "known logs" (CT log list v3)
// JSON schema needed to attribute a log to the operator that runs it. The real
// document (https://www.gstatic.com/ct/log_list/v3/log_list.json) carries far
// more per-log detail (keys, states, temporal intervals); only the operator name
// and each log's base URL are read here. Both classic RFC 6962 logs (under
// "logs") and static/tiled logs (under "tiled_logs") are parsed so an operator
// name is available regardless of a log's type.
type logList struct {
	Operators []struct {
		Name string `json:"name"`
		Logs []struct {
			URL string `json:"url"`
		} `json:"logs"`
		TiledLogs []struct {
			SubmissionURL string `json:"submission_url"`
			MonitoringURL string `json:"monitoring_url"`
		} `json:"tiled_logs"`
	} `json:"operators"`
}

// LoadOperatorMap parses a Google/Chrome-style CT log-list v3 JSON document and
// returns a map from each log's normalized base URL (see NormalizeLogURL) to the
// name of the operator that runs it. It lets a deployment attribute its
// configured logs to operators for a CT operator-diversity policy without
// hand-copying every operator name: a configured log whose "operator" is not set
// explicitly inherits it from this list by URL match (ApplyOperators).
//
// A malformed document is an error; a well-formed one with no usable
// operator/url pairs is also an error, so pointing at the wrong file fails
// loudly rather than silently attributing nothing. Duplicate URLs across
// operators (which should not occur in a well-formed list) resolve to the first
// operator seen.
func LoadOperatorMap(data []byte) (map[string]string, error) {
	var ll logList
	if err := json.Unmarshal(data, &ll); err != nil {
		return nil, fmt.Errorf("parsing CT log list: %w", err)
	}
	out := make(map[string]string)
	add := func(operator, rawURL string) {
		operator = strings.TrimSpace(operator)
		key := NormalizeLogURL(rawURL)
		if operator == "" || key == "" {
			return
		}
		if _, exists := out[key]; !exists {
			out[key] = operator
		}
	}
	for _, o := range ll.Operators {
		for _, l := range o.Logs {
			add(o.Name, l.URL)
		}
		for _, l := range o.TiledLogs {
			add(o.Name, l.SubmissionURL)
			add(o.Name, l.MonitoringURL)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("CT log list contained no operator/url entries")
	}
	return out, nil
}

// NormalizeLogURL canonicalizes a CT log base URL for matching between a
// configured log and a log-list entry: it trims surrounding whitespace and any
// trailing slash so "https://ct.example/log/" and "https://ct.example/log"
// compare equal (the log list publishes trailing-slash URLs).
func NormalizeLogURL(u string) string {
	return strings.TrimRight(strings.TrimSpace(u), "/")
}

// ApplyOperators fills the Operator of any log in logs whose Operator is empty
// from operatorsByURL (as returned by LoadOperatorMap), matching on normalized
// base URL. Logs with an explicit Operator are left untouched, so operator
// config always wins over the imported list. It returns the number of logs that
// were assigned an operator from the list.
func ApplyOperators(logs []LogConfig, operatorsByURL map[string]string) int {
	filled := 0
	for i := range logs {
		if strings.TrimSpace(logs[i].Operator) != "" {
			continue
		}
		if op, ok := operatorsByURL[NormalizeLogURL(logs[i].URL)]; ok {
			logs[i].Operator = op
			filled++
		}
	}
	return filled
}
