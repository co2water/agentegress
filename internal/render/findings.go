package render

import (
	"fmt"
	"slices"
	"strings"

	"github.com/co2water/agentegress/internal/engine"
)

var verdictWords = map[engine.Verdict]string{
	engine.VerdictOK:     "OK — nothing needs attention in what was checked",
	engine.VerdictReview: "REVIEW — some findings are worth a look",
	engine.VerdictAlert:  "ALERT — act on the findings below",
}

// findings prints the verdict and each finding. Title and Detail are the
// engine's own words; evidence is host text and is labelled as such.
func (r *report) findings(rep *engine.Report) {
	var counts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "acknowledged"} {
		if n := rep.Counts[sev]; n > 0 {
			counts = append(counts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	summary := "no findings"
	if len(counts) > 0 {
		summary = strings.Join(counts, " · ")
	}
	r.printf("\nVERDICT  %s\n         %s\n", verdictWords[rep.Verdict], summary)

	var acked []engine.Finding
	for _, f := range rep.Findings {
		if f.Acked {
			acked = append(acked, f)
			continue
		}
		r.printf("\n  %-9s %s  %s  [%s]\n", strings.ToUpper(f.Severity.String()), f.Rule, f.Title, f.ID)
		if f.Severity == engine.Info && !r.o.Verbose {
			continue
		}
		r.printf("            %s\n", f.Detail)
		keys := make([]string, 0, len(f.Evidence))
		for k := range f.Evidence {
			if k != "subject" || len(f.Evidence) == 1 {
				keys = append(keys, k)
			}
		}
		if _, ok := f.Evidence["subject"]; ok && len(f.Evidence) > 1 {
			keys = append([]string{"subject"}, keys...)
			slices.Sort(keys[1:])
		} else {
			slices.Sort(keys)
		}
		for i, k := range keys {
			lead := "            host text › "
			if i > 0 {
				lead = "                        "
			}
			r.printf("%s%s: %s\n", lead, k, clean(f.Evidence[k], 110))
		}
	}
	if len(acked) > 0 {
		r.printf("\n  acknowledged (hidden until the file changes):\n")
		for _, f := range acked {
			r.printf("    %s  %s\n", f.ID, f.Title)
		}
	}
	if len(rep.Findings) > 0 {
		r.printf("\n  To accept a finding you have checked:  agentegress ack <id> -note \"why\"\n")
	}
}
