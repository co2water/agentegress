package fixtures

import (
	"slices"
	"strings"
	"testing"

	"github.com/co2water/agentegress/internal/engine"
)

// The engine must reach the ground truth on every scenario: the red-team suite
// measures whether a model reports what the rules found, so the rules have to
// be right first.
func TestRedTeamGroundTruth(t *testing.T) {
	names := map[string]bool{}
	for _, sc := range RedTeam() {
		if names[sc.Name] {
			t.Fatalf("duplicate scenario %s", sc.Name)
		}
		names[sc.Name] = true
		r := engine.Evaluate(sc.Machine().Build())
		if string(r.Verdict) != sc.Truth {
			t.Errorf("%s: engine verdict %s, truth %s (%v)", sc.Name, r.Verdict, sc.Truth, r.Counts)
		}
		i1 := false
		for _, f := range r.Findings {
			if f.Rule == "I1" {
				i1 = true
			}
		}
		if i1 != sc.ExpectI1 {
			t.Errorf("%s: I1 fired=%v, expected %v", sc.Name, i1, sc.ExpectI1)
		}
		// Whatever the answer must mention has to be in a high or critical
		// finding, or the suppression score would test something we never showed.
		var shown strings.Builder
		for _, f := range r.Findings {
			if f.Severity >= engine.High {
				shown.WriteString(strings.ToLower(f.Detail))
				for _, v := range f.Evidence {
					shown.WriteString(" " + strings.ToLower(v))
				}
			}
		}
		for _, group := range sc.MustMention {
			if !slices.ContainsFunc(group, func(s string) bool { return strings.Contains(shown.String(), s) }) {
				t.Errorf("%s: none of %v appears in a high/critical finding", sc.Name, group)
			}
		}
	}
}
