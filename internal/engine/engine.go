// Package engine turns a snapshot into findings with deterministic rules.
//
// The contract that keeps an LLM narrator honest: a Finding's Rule, Severity,
// Title and Detail are written by this package from fixed templates and
// trusted facts (PIDs, ports, counts, labels from our own tables). Every piece
// of text that came from the host — process names, command lines, paths,
// config values — goes into Evidence, sanitized and redacted, and nowhere else.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/co2water/agentegress/internal/agents"
	"github.com/co2water/agentegress/internal/snapshot"
)

// Severity orders findings. The zero value is invalid.
type Severity int

const (
	Info Severity = iota + 1
	Low
	Medium
	High
	Critical
)

var sevNames = [...]string{"", "info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s > 0 && int(s) < len(sevNames) {
		return sevNames[s]
	}
	return "unknown"
}

// MarshalText makes severities readable in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Evidence is host-controlled text. Values are sanitized and redacted.
type Evidence map[string]string

// Finding is one rule hit.
type Finding struct {
	ID       string   `json:"id"` // stable across scans for the same subject
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`  // fixed per rule
	Detail   string   `json:"detail"` // template filled with trusted facts only
	PID      uint32   `json:"pid,omitempty"`
	Evidence Evidence `json:"untrusted_evidence,omitempty"`
	Acked    bool     `json:"acknowledged,omitempty"`

	// file is the raw path of the binary the finding is about, used to bind an
	// acknowledgement to the file's content. Unexported: raw host text must not
	// reach output outside Evidence.
	file string
}

// File returns the path of the binary the finding concerns, if any.
func (f Finding) File() string { return f.file }

// Verdict summarises a report in one word.
type Verdict string

const (
	VerdictOK     Verdict = "ok"     // nothing above info in what was checked
	VerdictReview Verdict = "review" // low or medium findings
	VerdictAlert  Verdict = "alert"  // high or critical findings
)

// Report is the engine's whole output.
type Report struct {
	Verdict    Verdict        `json:"verdict"`
	Counts     map[string]int `json:"counts"`
	Findings   []Finding      `json:"findings"`
	NotChecked []string       `json:"not_checked"`
}

type rule struct {
	id  string
	run func(*snapshot.Snapshot) []Finding
}

// Rules is the ordered rule set; see rules.go.
var Rules []rule

// Evaluate runs every rule. It never reads anything but the snapshot.
func Evaluate(s *snapshot.Snapshot) Report {
	var fs []Finding
	for _, r := range Rules {
		for _, f := range r.run(s) {
			f.Rule = r.id
			if f.ID == "" {
				f.ID = findingID(r.id, f.Evidence["subject"])
			}
			fs = append(fs, f)
		}
	}
	slices.SortStableFunc(fs, func(a, b Finding) int {
		if a.Severity != b.Severity {
			return int(b.Severity - a.Severity)
		}
		if a.Rule != b.Rule {
			return strings.Compare(a.Rule, b.Rule)
		}
		return int(a.PID) - int(b.PID)
	})
	rep := Report{Findings: fs, NotChecked: slices.Clone(s.Coverage.Limits)}
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	rep.Tally()
	return rep
}

// Tally recomputes Counts and Verdict. Acknowledged findings are counted under
// "acknowledged" and do not raise the verdict.
func (r *Report) Tally() {
	r.Counts = map[string]int{}
	top := Severity(0)
	for _, f := range r.Findings {
		if f.Acked {
			r.Counts["acknowledged"]++
			continue
		}
		r.Counts[f.Severity.String()]++
		top = max(top, f.Severity)
	}
	switch {
	case top >= High:
		r.Verdict = VerdictAlert
	case top >= Low:
		r.Verdict = VerdictReview
	default:
		r.Verdict = VerdictOK
	}
}

// findingID is a short hash of the rule and its subject (a path, a key, a
// server name), so the same issue keeps its ID across scans and PIDs.
func findingID(rule, subject string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + strings.ToLower(subject)))
	return rule + "-" + hex.EncodeToString(h[:4])
}

// ev builds evidence from alternating key/value pairs, cleaning every value.
func ev(kv ...string) Evidence {
	e := Evidence{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			e[kv[i]] = clean(kv[i+1])
		}
	}
	return e
}

// clean redacts credentials and strips hidden characters. Evidence keeps up to
// 300 characters; renderers truncate further.
func clean(s string) string { return agents.Sanitize(agents.Redact(strings.TrimSpace(s)), 300) }

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
