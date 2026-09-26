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

func serverFor(s *snapshot.Snapshot) *mcp.Server {
	r := engine.Evaluate(s)
	return NewServer(func() (*snapshot.Snapshot, engine.Report, error) { return s, r, nil }, "test")
}

func callTool(t *testing.T, srv *mcp.Server, name string, args map[string]any) (map[string]any, string) {
	t.Helper()
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args}})
	var out strings.Builder
	init := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	if err := srv.Serve(strings.NewReader(init+"\n"+string(req)+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var resp map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &resp); err != nil {
		t.Fatal(err)
	}
	res := resp["result"].(map[string]any)
	if res["isError"] == true {
		t.Fatalf("%s returned an error: %v", name, res["content"])
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	return res["structuredContent"].(map[string]any), text
}

var allCalls = []struct {
	name string
	args map[string]any
}{
	{"scan_summary", nil},
	{"list_findings", map[string]any{"include_acknowledged": true}},
	{"list_agents", map[string]any{"all_processes": true}},
	{"list_agents", nil},
	{"list_connections", map[string]any{"include_loopback": true}},
	{"list_connections", map[string]any{"agents_only": true}},
	{"explain_process", map[string]any{"pid": float64(2120)}},
	{"explain_process", map[string]any{"pid": float64(3000)}},
	{"explain_process", map[string]any{"pid": float64(2110)}},
	{"list_listening_ports", nil},
	{"list_autostarts", map[string]any{"problems_only": false}},
	{"login_activity", nil},
}

// TestEnvelope is the output contract: host text only under untrusted keys.
func TestEnvelope(t *testing.T) {
	const marker = "ZZHOSTTEXT"
	s := fixtures.Marked(marker).Build()
	srv := serverFor(s)
	seen := 0
	for _, c := range allCalls {
		structured, text := callTool(t, srv, c.name, c.args)
		if !strings.HasPrefix(text, "agentegress result.") {
			t.Errorf("%s: preamble missing", c.name)
		}
		if strings.Contains(text, marker) {
			seen++
		}
		if p := fixtures.Leak(structured, marker, c.name, false); p != "" {
			t.Errorf("host text outside the envelope at %s", p)
		}
	}
	if seen < len(allCalls)-2 {
		t.Errorf("marker appeared in only %d/%d results: the fixture is not exercising the envelope", seen, len(allCalls))
	}
}

func TestSummaryMustReport(t *testing.T) {
	s := fixtures.Marked("X").Build()
	structured, _ := callTool(t, serverFor(s), "scan_summary", nil)
	if structured["verdict"] != "alert" {
		t.Fatalf("verdict = %v", structured["verdict"])
	}
	rules := map[string]bool{}
	for _, m := range structured["must_report"].([]any) {
		rules[m.(map[string]any)["rule"].(string)] = true
	}
	for _, want := range []string{"I1", "A1", "A3", "H4", "H3"} {
		if !rules[want] {
			t.Errorf("must_report lacks %s: %v", want, rules)
		}
	}
	nc := structured["not_checked"].([]any)
	if len(nc) == 0 {
		t.Error("not_checked is empty")
	}
}

func TestCleanBaseline(t *testing.T) {
	structured, _ := callTool(t, serverFor(fixtures.Base().Build()), "scan_summary", nil)
	if structured["verdict"] != "ok" || len(structured["must_report"].([]any)) != 0 {
		t.Fatalf("baseline summary = %v", structured)
	}
	ag := structured["agents"].([]any)
	if len(ag) != 1 || ag[0].(map[string]any)["agent"] != "Claude Desktop" {
		t.Errorf("agents = %v", ag)
	}
	tree, _ := callTool(t, serverFor(fixtures.Base().Build()), "list_agents", nil)
	b, _ := json.Marshal(tree)
	if !strings.Contains(string(b), `"mcp_config_name":"github"`) || !strings.Contains(string(b), `"peer_org":"Anthropic"`) {
		t.Errorf("tree lacks MCP name or peer org: %s", b)
	}
}

func TestArgumentValidation(t *testing.T) {
	srv := serverFor(fixtures.Base().Build())
	for _, c := range []struct {
		name string
		args map[string]any
	}{
		{"explain_process", map[string]any{}},
		{"explain_process", map[string]any{"pid": "12; rm -rf"}},
		{"explain_process", map[string]any{"pid": float64(-1)}},
		{"explain_process", map[string]any{"pid": 1.5}},
		{"explain_process", map[string]any{"pid": float64(999999)}},
		{"list_findings", map[string]any{"min_severity": "extreme"}},
	} {
		req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": c.name, "arguments": c.args}})
		var out strings.Builder
		srv.Serve(strings.NewReader(string(req)+"\n"), &out)
		if !strings.Contains(out.String(), `"isError":true`) {
			t.Errorf("%s(%v) accepted: %s", c.name, c.args, out.String())
		}
	}
}
