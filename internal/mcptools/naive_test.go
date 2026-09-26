package mcptools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/co2water/agentegress/internal/engine"
	"github.com/co2water/agentegress/internal/fixtures"
	"github.com/co2water/agentegress/internal/mcp"
	"github.com/co2water/agentegress/internal/snapshot"
)

// Audit finding: the naive baseline used to get less data than the real
// server, so part of the measured gap was data, not design. Every fact class
// the real server shows must also reach the baseline.
func TestNaiveGetsTheSameFacts(t *testing.T) {
	m := fixtures.Marked("MK")
	m.Proc(2170, 2100, "rundll32.exe", `C:\Windows\System32\rundll32.exe`,
		`rundll32.exe C:\Users\alice\AppData\Roaming\x.dll,Run`, fixtures.Signed("Microsoft Windows"))
	m.Conn(2170, "203.0.113.70:443", "")
	s := m.Build()
	r := engine.Evaluate(s)
	srv := NewNaiveServer(func() (*snapshot.Snapshot, engine.Report, error) { return s, r, nil }, "t")

	var all strings.Builder
	for _, tool := range []string{"get_processes", "get_autostarts", "get_mcp_configs", "get_host_security"} {
		all.WriteString(callRaw(t, srv, tool))
	}
	out := all.String()
	for _, fact := range []string{
		`"peer_org":"Anthropic"`,         // provider labels
		`"under_agent":"Claude Code"`,    // agent attribution
		`"mcp_config_name":"github"`,     // MCP attribution
		`"in_user_writable_dir":true`,    // writable-folder flag
		`"runs_file":`,                   // script-host payload
		`"listening_on":"0.0.0.0:7777"`,  // listeners
		`"rdp_enabled":true`,             // host settings
		`"firewall_disabled_profiles":[`, // firewall
		`"failed":[`,                     // logons
		`"not_checked":[`,                // coverage limits
	} {
		if !strings.Contains(out, fact) {
			t.Errorf("baseline lacks %s", fact)
		}
	}
	// And it must stay a baseline: no verdict, findings or envelope.
	for _, design := range []string{`"verdict"`, `"must_report"`, `"untrusted"`, "agentegress result."} {
		if strings.Contains(out, design) {
			t.Errorf("baseline exposes design feature %s", design)
		}
	}
}

func callRaw(t *testing.T, srv *mcp.Server, name string) string {
	t.Helper()
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": map[string]any{}}})
	var out strings.Builder
	init := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	if err := srv.Serve(strings.NewReader(init+"\n"+string(req)+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var resp struct {
		Result struct {
			Structured json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &resp); err != nil {
		t.Fatal(err)
	}
	return string(resp.Result.Structured)
}
