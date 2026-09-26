package mcptools

import (
	"testing"

	"github.com/co2water/agentegress/internal/collect"
	"github.com/co2water/agentegress/internal/fixtures"
)

// Third code review (2026-09-26), item 12: list_autostarts ignored the host
// program's signature and listed entries that were never checked as problems.
func TestThirdReviewAutostartProblems(t *testing.T) {
	m := fixtures.Base()
	host := `C:\Users\alice\tools\wscript.exe`
	m.Sign(host, collect.Signature{Status: collect.SigUnsigned})
	m.Autostart(collect.Autostart{Kind: "run-key", Scope: "user", Name: "hosted",
		Command: host + ` C:\Users\alice\tools\ok.js`, Target: `C:\Users\alice\tools\ok.js`, Host: host},
		&collect.Signature{Status: collect.SigSigned, Signer: "Acme"})
	m.Autostart(collect.Autostart{Kind: "service", Scope: "machine", Name: "sys",
		Command: `C:\Windows\System32\svchost.exe -k x`, Target: `C:\Windows\System32\svchost.exe`}, nil)
	s := m.Build()

	res, _ := callTool(t, serverFor(s), "list_autostarts", nil)
	rows := res["autostarts"].([]any)
	if len(rows) != 1 {
		t.Fatalf("problems = %d rows %v, want only the entry with the unsigned host", len(rows), rows)
	}
	row := rows[0].(map[string]any)
	if row["host_signature"] != "unsigned" {
		t.Errorf("row = %v", row)
	}
	if n, _ := res["not_checked"].(float64); n < 1 {
		t.Errorf("not_checked = %v, want the System32 service counted", res["not_checked"])
	}
}
