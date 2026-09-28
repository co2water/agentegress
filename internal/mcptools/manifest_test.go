package mcptools

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/co2water/agentegress/internal/engine"
	"github.com/co2water/agentegress/internal/fixtures"
	"github.com/co2water/agentegress/internal/snapshot"
)

// The Claude Desktop extension manifest lists the tools for the install
// dialog; it must match what the server actually offers.
func TestMCPBManifestListsServerTools(t *testing.T) {
	b, err := os.ReadFile("../../packaging/mcpb/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		ManifestVersion string `json:"manifest_version"`
		Server          struct {
			Type      string `json:"type"`
			MCPConfig struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"mcp_config"`
		} `json:"server"`
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	if m.Server.Type != "binary" || !slices.Equal(m.Server.MCPConfig.Args, []string{"mcp"}) {
		t.Errorf("server config = %+v", m.Server)
	}
	var want []string
	for _, x := range m.Tools {
		want = append(want, x.Name)
	}

	s := fixtures.Base().Build()
	r := engine.Evaluate(s)
	srv := NewServer(func() (*snapshot.Snapshot, engine.Report, error) { return s, r, nil }, "test")
	var out strings.Builder
	in := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}` + "\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	if err := srv.Serve(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &resp); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range resp.Result.Tools {
		got = append(got, x.Name)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("manifest tools %v, server tools %v", want, got)
	}
}
