package snapshot_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/co2water/agentegress/internal/fixtures"
	"github.com/co2water/agentegress/internal/snapshot"
)

// Review finding #5: `scan -json` promised redaction but left autostarts,
// signers, logon names, MCP source/URL/env names and warnings raw. The marked
// fixture puts a secret-looking token and an invisible character into every
// host string; neither may survive anywhere in the redacted JSON.
func TestRedactedCoversEveryHostString(t *testing.T) {
	const secret = "--token=HUNTER2SECRET"
	const zw = "​"
	s := fixtures.Marked("MK" + zw + " " + secret).Build()
	s.Warnings = append(s.Warnings, "note "+secret+zw)
	b, err := json.Marshal(snapshot.Redacted(s))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if strings.Contains(out, "HUNTER2SECRET") {
		i := strings.Index(out, "HUNTER2SECRET")
		t.Errorf("secret survived near: %s", out[max(0, i-120):i+20])
	}
	if strings.Contains(out, zw) || strings.Contains(out, `​`) {
		t.Error("zero-width space survived")
	}
	if !strings.Contains(out, "MK") {
		t.Error("marker missing: fixture did not reach the output")
	}
}
