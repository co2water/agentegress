package render

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/co2water/agentegress/internal/agents"
	"github.com/co2water/agentegress/internal/collect"
	"github.com/co2water/agentegress/internal/snapshot"
)

func TestText(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	p := func(pid, ppid uint32, name, path, cmd string, n int) *collect.Process {
		return &collect.Process{PID: pid, PPID: ppid, Name: name, Path: path, Cmdline: cmd, Created: t0.Add(time.Duration(n) * time.Minute)}
	}
	desk := `C:\Program Files\WindowsApps\Claude_1\app\claude.exe`
	ap := netip.MustParseAddrPort
	in := snapshot.Input{
		Procs: map[uint32]*collect.Process{
			10: p(10, 1, "claude.exe", desk, desk, 1),
			11: p(11, 10, "claude.exe", desk, desk+" --type=utility", 2),
			20: p(20, 10, "claude.exe", `C:\Users\alice\AppData\Roaming\Claude\claude-code\claude.exe`, "claude", 3),
			22: p(22, 20, "node.exe", `C:\node\node.exe`, `node C:\npm\node_modules\@modelcontextprotocol\server-github\index.js --token ghp_abcdefgh12345678`, 4),
			23: p(23, 20, "weird.exe", `C:\Users\alice\AppData\Local\Temp\weird.exe`, "weird.exe --mcp", 5),
		},
		Conns: []collect.TCPConn{
			{PID: 11, State: collect.StateEstablished, Local: ap("10.0.0.2:1"), Remote: ap("160.79.104.10:443")},
			{PID: 22, State: collect.StateEstablished, Local: ap("10.0.0.2:2"), Remote: ap("140.82.112.6:443")},
			{PID: 23, State: collect.StateListen, Local: ap("0.0.0.0:8080")},
		},
		DNS:      map[netip.Addr][]string{netip.MustParseAddr("140.82.112.6"): {"api.github.com"}},
		Servers:  []agents.MCPServer{{Client: agents.ClaudeCode, Name: "github", Command: "npx", Args: []string{"@modelcontextprotocol/server-github"}}},
		UserDirs: []string{`c:\users\alice\`},
	}
	s := snapshot.Build(in, func(paths []string) map[string]collect.Signature {
		out := map[string]collect.Signature{}
		for _, x := range paths {
			if strings.Contains(x, "weird") {
				out[x] = collect.Signature{Status: collect.SigUnsigned}
			} else {
				out[x] = collect.Signature{Status: collect.SigSigned, Signer: "Acme"}
			}
		}
		return out
	})

	var b strings.Builder
	Text(&b, s, nil, Options{})
	out := b.String()

	for _, want := range []string{
		"■ Claude Desktop  pid 10  ✓ Acme",
		"   → 160.79.104.10:443  [Anthropic]", // helper's connection folded into the root
		"├─ Claude Code  claude.exe  pid 20",
		"MCP github  node.exe  pid 22",
		"→ api.github.com  140.82.112.6:443",
		"MCP?  weird.exe  pid 23  ✗ unsigned · in user-writable dir",
		"LISTEN 0.0.0.0:8080  ⚠ reachable from the network",
		"Claude Code  github  running ×1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "pid 11") {
		t.Errorf("helper process printed as its own node:\n%s", out)
	}
	if strings.Contains(out, "abcdefgh12345678") {
		t.Errorf("token leaked:\n%s", out)
	}
}
