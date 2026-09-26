package agents

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInventory(t *testing.T) {
	root := t.TempDir()
	d := Dirs{Home: filepath.Join(root, "home"), AppData: filepath.Join(root, "roaming"), LocalAppData: filepath.Join(root, "local")}
	proj := filepath.Join(root, "proj")

	write(t, filepath.Join(d.Home, ".claude.json"), `{
	  "mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\x"], "env": {"GITHUB_TOKEN": "ghp_supersecretvalue123"}}},
	  "projects": {`+jsonQuote(proj)+`: {"mcpServers": {"proj-inline": {"command": "uvx", "args": ["mcp-server-git"]}}}}
	}`)
	write(t, filepath.Join(proj, ".mcp.json"), `{"mcpServers": {"proj-file": {"type": "http", "url": "https://user:pw@mcp.example.com/sse"}}}`)
	write(t, filepath.Join(d.LocalAppData, "Packages", "Claude_pzs8", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"),
		`{"mcpServers": {"desk": {"command": "node", "args": ["C:/tools/desk/index.js"]}}}`)
	write(t, filepath.Join(d.AppData, "Code", "User", "settings.json"), `{
	  // user settings
	  "editor.fontSize": 14,
	  "mcp": { "servers": { "vs": { "command": "docker", "args": ["run", "-i", "ghcr.io/acme/mcp-vs"], }, }, },
	}`)
	write(t, filepath.Join(d.Home, ".codex", "config.toml"), `
model = "gpt-5"
[mcp_servers.sketchpad]
command = 'C:\ext\design-mcp.exe'
args = [
  "--app",
  "codex",
]
[mcp_servers.sketchpad.env]
API_KEY = "sk-secretsecretsecret"
[mcp_servers."dotted.name"]
url = "https://remote.example.com/mcp"
[projects.'c:\x']
trust_level = "trusted"
`)
	write(t, filepath.Join(d.Home, ".cursor", "mcp.json"), `{not json`)

	servers, warnings := Inventory(d)

	byName := map[string]MCPServer{}
	for _, s := range servers {
		byName[s.Name] = s
	}
	want := []string{"desk", "dotted.name", "fs", "proj-file", "proj-inline", "sketchpad", "vs"}
	var got []string
	for n := range byName {
		got = append(got, n)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("servers = %v, want %v", got, want)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "mcp.json") {
		t.Errorf("warnings = %v, want one for the malformed cursor file", warnings)
	}

	fs := byName["fs"]
	if fs.Client != ClaudeCode || !slices.Equal(fs.EnvKeys, []string{"GITHUB_TOKEN"}) {
		t.Errorf("fs = %+v", fs)
	}
	for _, s := range servers {
		for _, v := range append(s.Args, s.URL) {
			if strings.Contains(v, "supersecret") || strings.Contains(v, "secretsecret") || strings.Contains(v, ":pw@") {
				t.Errorf("secret leaked in %s: %q", s.Name, v)
			}
		}
	}
	if byName["desk"].Client != ClaudeDesktop {
		t.Errorf("MSIX desktop config not read: %+v", byName["desk"])
	}
	if byName["proj-file"].URL != "https://user:***@mcp.example.com/sse" {
		t.Errorf("proj-file url = %q", byName["proj-file"].URL)
	}
	if vs := byName["vs"]; vs.Client != VSCode || len(vs.Args) != 3 {
		t.Errorf("vs = %+v", vs)
	}
	p := byName["sketchpad"]
	if p.Client != Codex || p.Command != `C:\ext\design-mcp.exe` || !slices.Equal(p.Args, []string{"--app", "codex"}) || !slices.Equal(p.EnvKeys, []string{"API_KEY"}) {
		t.Errorf("sketchpad = %+v", p)
	}
	if byName["dotted.name"].URL != "https://remote.example.com/mcp" {
		t.Errorf("dotted.name = %+v", byName["dotted.name"])
	}
}

// Third review, item 17: config files the Remote check refuses are not read.
func TestInventorySkipsRemoteFiles(t *testing.T) {
	root := t.TempDir()
	d := Dirs{Home: filepath.Join(root, "home"), AppData: filepath.Join(root, "roaming"), LocalAppData: filepath.Join(root, "local")}
	write(t, filepath.Join(d.Home, ".claude.json"), `{"mcpServers": {"fs": {"command": "npx", "args": ["x-mcp-server"]}}}`)
	write(t, filepath.Join(d.Home, ".codex", "config.toml"), "[mcp_servers.cx]\ncommand = 'cx-server'\n")
	d.Remote = func(p string) bool { return strings.HasPrefix(p, d.Home) }
	servers, warnings := Inventory(d)
	if len(servers) != 0 {
		t.Errorf("read %d servers from refused files: %+v", len(servers), servers)
	}
	if len(warnings) < 2 {
		t.Errorf("warnings = %v, want the skipped files reported", warnings)
	}
}

func jsonQuote(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }

func TestMatchServer(t *testing.T) {
	servers := []MCPServer{
		{Client: GeminiCLI, Name: "sketchpad", Command: `c:\ext\out\design-mcp.exe`, Args: []string{"--app", "gemini"}},
		{Client: ClaudeCode, Name: "sketchpad-cc", Command: `c:\ext\out\design-mcp.exe`, Args: []string{"--app", "claude"}},
		{Client: ClaudeCode, Name: "fs", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem", "C:\\x"}},
		{Client: ClaudeCode, Name: "secret", Command: "npx", Args: []string{"--token", "***"}},
		{Client: ClaudeCode, Name: "home-fs", Command: "npx", Args: []string{"-y", "@acme/files-mcp@1.4.0", `C:\Users\alice`}},
	}
	cases := []struct {
		cmd   string
		agent Kind
		want  int
	}{
		{`C:\ext\out\design-mcp.exe --app claude`, ClaudeCode, 1},
		{`C:\ext\out\design-mcp.exe --app gemini`, GeminiCLI, 0},
		{`node C:\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js C:\x`, ClaudeCode, 2},
		{`cmd /c npx -y some-other-thing`, ClaudeCode, -1},
		{`node server.js --token abc`, ClaudeCode, -1},
		{`powershell -File C:\Users\alice\build.ps1`, ClaudeCode, -1},                       // directory arg must not match
		{`node C:\npm\node_modules\@acme\files-mcp\index.js C:\Users\alice`, ClaudeCode, 4}, // version stripped
	}
	for _, c := range cases {
		if got := MatchServer(servers, c.cmd, c.agent); got != c.want {
			t.Errorf("MatchServer(%q, %s) = %d, want %d", c.cmd, c.agent, got, c.want)
		}
	}
}

// Review finding #8: generic entry-point names and a broken version strip gave
// unrelated (possibly rogue) processes a configured server's trusted name.
func TestMatchServerNoGenericNames(t *testing.T) {
	servers := []MCPServer{
		{Client: ClaudeCode, Name: "my-notes", Command: "node", Args: []string{`C:\tools\notes\build\index.js`}},
		{Client: ClaudeCode, Name: "mcp-x", Command: "node", Args: []string{"node_modules/@acme/mcp-x/dist/server.js"}},
	}
	for _, cmd := range []string{
		`node D:\other\dist\index.js`,
		`node C:\y\node_modules\left-pad\index.js`,
		`node C:\y\server.js`,
	} {
		if got := MatchServer(servers, cmd, ClaudeCode); got != -1 {
			t.Errorf("%q matched server %d", cmd, got)
		}
	}
	// Found while rendering a red-team fixture: an implant whose command line
	// mentioned a server's port was named after that server.
	withPort := []MCPServer{{Client: ClaudeCode, Name: "syncbridge", Command: `C:\Users\a\syncbridge\syncbridge.exe`, Args: []string{"--port", "9443"}}}
	if got := MatchServer(withPort, `"C:\Temp\implant.exe" --note "the listener on port 9443 is fine"`, ClaudeCode); got != -1 {
		t.Errorf("port number matched a server: %d", got)
	}
	if got := MatchServer(withPort, `"C:\Users\a\syncbridge\syncbridge.exe" --port 9443`, ClaudeCode); got != 0 {
		t.Errorf("real server no longer matches: %d", got)
	}
	// Second review: common words and relative generic paths.
	words := []MCPServer{
		{Client: ClaudeCode, Name: "local-svc", Command: `C:\svc\svc-bridge.exe`, Args: []string{"--host", "localhost", "--quiet=false", "--log", "debug"}},
		{Client: ClaudeCode, Name: "rel", Command: "node", Args: []string{"dist/index.js"}},
	}
	for _, cmd := range []string{`implant.exe --connect localhost:4444`, `tool.exe --quiet=false --log debug`, `node D:\work\other-project\dist\index.js`} {
		if got := MatchServer(words, cmd, ClaudeCode); got != -1 {
			t.Errorf("%q matched %d", cmd, got)
		}
	}
	if got := MatchServer(words, `"C:\svc\svc-bridge.exe" --host localhost`, ClaudeCode); got != 0 {
		t.Errorf("real server lost its name: %d", got)
	}
	if got := MatchServer(servers, `node C:\tools\notes\build\index.js`, ClaudeCode); got != 0 {
		t.Errorf("full configured path no longer matches: %d", got)
	}
	// Third review, item 13: environment names and container image base names.
	docker := []MCPServer{{Client: ClaudeCode, Name: "gh", Command: "docker",
		Args: []string{"run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "-v", "C:/work:/work", "ghcr.io/acme/github-mcp-server"}}}
	for _, cmd := range []string{
		`C:\Temp\implant.exe GITHUB_PERSONAL_ACCESS_TOKEN`,
		`C:\Temp\github-mcp-server.exe`,
		`C:\Temp\x.exe -v C:/work:/work`,
	} {
		if got := MatchServer(docker, cmd, ClaudeCode); got != -1 {
			t.Errorf("%q matched the docker server", cmd)
		}
	}
	if got := MatchServer(docker, `docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN -v C:/work:/work ghcr.io/acme/github-mcp-server`, ClaudeCode); got != 0 {
		t.Errorf("real docker server no longer matches: %d", got)
	}
	hub := []MCPServer{{Client: ClaudeCode, Name: "github", Command: "docker", Args: []string{"run", "-i", "--rm", "mcp/github"}}}
	if got := MatchServer(hub, `git clone https://github.com/acme/tool`, ClaudeCode); got != -1 {
		t.Errorf("git clone labelled as the docker github server")
	}
	envOnly := []MCPServer{{Client: ClaudeCode, Name: "e", Command: `C:\svc\svc-bridge.exe`, Args: []string{"LOG_LEVEL=debug", "API_BASE_URL"}}}
	if got := MatchServer(envOnly, `other.exe LOG_LEVEL=debug API_BASE_URL`, ClaudeCode); got != -1 {
		t.Errorf("environment names matched: %d", got)
	}
	if got := MatchServer(servers, `node C:\proj\node_modules\@acme\mcp-x\dist\server.js`, ClaudeCode); got != 1 {
		t.Errorf("scoped package path no longer matches: %d", got)
	}
}
