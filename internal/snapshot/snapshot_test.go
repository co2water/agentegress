package snapshot

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/co2water/agentegress/internal/agents"
	"github.com/co2water/agentegress/internal/collect"
)

var t0 = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

func proc(pid, ppid uint32, name, path, cmd string, age time.Duration) *collect.Process {
	return &collect.Process{PID: pid, PPID: ppid, Name: name, Path: path, Cmdline: cmd, Created: t0.Add(age)}
}

func input() Input {
	desk := `C:\Program Files\WindowsApps\Claude_1\app\claude.exe`
	return Input{
		Procs: map[uint32]*collect.Process{
			1:  proc(1, 0, "explorer.exe", `C:\Windows\explorer.exe`, "explorer", 0),
			10: proc(10, 1, "claude.exe", desk, `"`+desk+`"`, time.Minute),
			11: proc(11, 10, "claude.exe", desk, `"`+desk+`" --type=utility --utility-sub-type=network.mojom.NetworkService`, 2*time.Minute),
			20: proc(20, 10, "claude.exe", `C:\Users\alice\AppData\Roaming\Claude\claude-code\2.1\claude.exe`, "claude --output-format stream-json", 3*time.Minute),
			21: proc(21, 20, "cmd.exe", `C:\Windows\System32\cmd.exe`, `cmd /c npx -y @modelcontextprotocol/server-github`, 4*time.Minute),
			22: proc(22, 21, "node.exe", `C:\Program Files\nodejs\node.exe`, `node C:\npm\node_modules\@modelcontextprotocol\server-github\dist\index.js`, 5*time.Minute),
			23: proc(23, 20, "weird.exe", `C:\Users\alice\AppData\Local\Temp\weird.exe`, `weird.exe --mcp`, 6*time.Minute),
			// PID 30 claims parent 20, but 20 was created after it: parent PID reuse.
			30: proc(30, 20, "orphan.exe", `C:\x\orphan.exe`, "orphan", time.Second),
			40: proc(40, 1, "chrome.exe", `C:\Program Files\Google\chrome.exe`, "chrome", 0),
		},
		Conns: []collect.TCPConn{
			{PID: 11, State: collect.StateEstablished, Local: ap("10.0.0.2:5000"), Remote: ap("160.79.104.10:443")},
			{PID: 22, State: collect.StateEstablished, Local: ap("10.0.0.2:5001"), Remote: ap("140.82.112.6:443")},
			{PID: 23, State: collect.StateListen, Local: ap("0.0.0.0:8080")},
			{PID: 20, State: collect.StateEstablished, Local: ap("127.0.0.1:5002"), Remote: ap("127.0.0.1:9000")},
			{PID: 40, State: collect.StateEstablished, Local: ap("10.0.0.2:5003"), Remote: ap("142.250.1.1:443")},
		},
		DNS: map[netip.Addr][]string{
			netip.MustParseAddr("160.79.104.10"): {"api.anthropic.com"},
			netip.MustParseAddr("140.82.112.6"):  {"api.github.com"},
		},
		Servers: []agents.MCPServer{
			{Client: agents.ClaudeCode, Name: "github", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github"}},
		},
		UserDirs: []string{`c:\users\alice\`},
	}
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestUnreadableChildNotAttributed(t *testing.T) {
	in := input()
	in.Procs[50] = &collect.Process{PID: 50, PPID: 20, Name: "ghost.exe"} // unreadable: no path, no time
	s := Build(in, nil)
	if s.Procs[50].Parent != 0 || s.Procs[50].Root != 0 {
		t.Errorf("unverifiable child attributed to agent tree: parent=%d root=%d", s.Procs[50].Parent, s.Procs[50].Root)
	}
}

func TestLoadRoundTrip(t *testing.T) {
	s := Build(input(), nil)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Procs[20].Children, s.Procs[20].Children) || got.Procs[22].Parent != 21 || got.Procs[30].Parent != 0 {
		t.Errorf("children %v vs %v, parent %d", got.Procs[20].Children, s.Procs[20].Children, got.Procs[22].Parent)
	}
	if got.Procs[22].MCP != "github" || len(got.Conns) != len(s.Conns) || got.Roots[0] != 10 {
		t.Errorf("round trip lost data: %+v", got.Procs[22])
	}
}

func TestBuild(t *testing.T) {
	var verified []string
	s := Build(input(), func(paths []string) map[string]collect.Signature {
		verified = paths
		out := map[string]collect.Signature{}
		for _, p := range paths {
			out[p] = collect.Signature{Status: collect.SigSigned}
		}
		return out
	})

	if len(s.Roots) != 1 || s.Roots[0] != 10 {
		t.Fatalf("roots = %v, want [10]", s.Roots)
	}
	p := s.Procs
	if p[10].Agent != agents.ClaudeDesktop || p[20].Agent != agents.ClaudeCode {
		t.Errorf("agents: 10=%q 20=%q", p[10].Agent, p[20].Agent)
	}
	if !p[11].Helper || p[20].Helper {
		t.Errorf("helper flags: 11=%v 20=%v", p[11].Helper, p[20].Helper)
	}
	if p[22].Root != 10 || p[22].Owner != agents.ClaudeCode {
		t.Errorf("22 root/owner = %d/%q", p[22].Root, p[22].Owner)
	}
	if p[21].MCP != "github" || p[22].MCP != "github" || p[23].MCP != "?" {
		t.Errorf("mcp: 21=%q 22=%q 23=%q", p[21].MCP, p[22].MCP, p[23].MCP)
	}
	if p[30].Parent != 0 || p[30].Root != 0 {
		t.Errorf("reused-PID parent accepted: parent=%d root=%d", p[30].Parent, p[30].Root)
	}
	if !p[23].UserDir || p[22].UserDir {
		t.Errorf("user dir: 23=%v 22=%v", p[23].UserDir, p[22].UserDir)
	}
	if p[40].Root != 0 || p[40].Signature == nil {
		t.Errorf("chrome: root=%d sig=%v (external conn should be verified)", p[40].Root, p[40].Signature)
	}
	if p[1].Signature != nil {
		t.Errorf("explorer verified without reason")
	}
	// 5 distinct agent-tree paths (both Desktop processes share one) + chrome.
	if len(verified) != 6 {
		t.Errorf("verified %d paths, want 6: %v", len(verified), verified)
	}

	var gh, lo, listen *Conn
	for i := range s.Conns {
		c := &s.Conns[i]
		switch c.PID {
		case 22:
			gh = c
		case 20:
			lo = c
		case 23:
			listen = c
		}
	}
	if gh == nil || !gh.External || len(gh.Hosts) != 1 || gh.Hosts[0] != "api.github.com" {
		t.Errorf("github conn = %+v", gh)
	}
	if lo == nil || lo.External {
		t.Errorf("loopback conn = %+v", lo)
	}
	if listen == nil || !listen.Exposed || listen.Remote != "" {
		t.Errorf("listener = %+v", listen)
	}
	if s.Coverage.AgentTree != 6 {
		t.Errorf("agent tree size = %d, want 6", s.Coverage.AgentTree)
	}
}
