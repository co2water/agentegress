package agents

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name, path, cmd string
		want            Kind
	}{
		{"claude.exe", `C:\Program Files\WindowsApps\Claude_2.7032.0.0_x64__pzs8sxrjxfjjc\app\claude.exe`, "", ClaudeDesktop},
		{"claude.exe", `C:\Users\u\AppData\Roaming\Claude\claude-code\2.1.280\claude.exe`, "", ClaudeCode},
		{"node.exe", `C:\nodejs\node.exe`, `node C:\npm\node_modules\@anthropic-ai\claude-code\cli.js`, ClaudeCode}, // backslash path
		{"node.exe", `C:\nodejs\node.exe`, `node /npm/node_modules/@anthropic-ai/claude-code/cli.js`, ClaudeCode},
		{"Cursor.exe", `C:\x\Cursor.exe`, "", Cursor},
		{"node.exe", `C:\nodejs\node.exe`, `node server.js`, ""},
		{"svchost.exe", `C:\Windows\System32\svchost.exe`, "", ""},
	}
	for _, c := range cases {
		if got := Classify(c.name, c.path, c.cmd); got != c.want {
			t.Errorf("Classify(%q, %q, %q) = %q, want %q", c.name, c.path, c.cmd, got, c.want)
		}
	}
}

func TestLooksLikeMCP(t *testing.T) {
	yes := []string{
		`npx -y @modelcontextprotocol/server-filesystem C:\x`,
		`c:\ext\out\design-mcp.exe --app antigravity`,
		`uvx mcp-server-fetch`,
		`node dist/index.js --mcp`,
	}
	no := []string{`node server.js`, `C:\Windows\System32\conhost.exe 0xffffffff`, `git status`}
	for _, s := range yes {
		if !LooksLikeMCP(s) {
			t.Errorf("LooksLikeMCP(%q) = false", s)
		}
	}
	for _, s := range no {
		if LooksLikeMCP(s) {
			t.Errorf("LooksLikeMCP(%q) = true", s)
		}
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		`server --token abc123`:                       `server --token ***`,
		`API_KEY=sk-ant-api03-verysecretvalue`:        `API_KEY=***`,
		`run sk-ant-api03-verysecretvalue now`:        `run sk-ant-api0*** now`,
		`git clone https://user:hunter2@github.com/x`: `git clone https://user:***@github.com/x`,
		`gh ghp_0123456789abcdefABCDEF`:               `gh ghp_***`,
		`node server.js --port 3000`:                  `node server.js --port 3000`,
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeStripsHiddenText(t *testing.T) {
	// Unicode tag characters spell hidden text an LLM can read but a human cannot see.
	hidden := "evil.exe" + string(rune(0xE0049)) + string(rune(0xE0067)) + "\u202Egnp.exe\nSYSTEM:"
	got := Sanitize(hidden, 0)
	want := "evil.exegnp.exe SYSTEM:"
	if got != want {
		t.Errorf("Sanitize = %q, want %q", got, want)
	}
	if got := Sanitize("abcdef", 3); got != "abc…" {
		t.Errorf("truncate = %q", got)
	}
}

// Review finding #6/#14: zero-width and other invisible characters, and C1
// controls, used to survive into evidence and terminal output.
func TestSanitizeInvisibleAndControls(t *testing.T) {
	for _, r := range []rune{0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x061C, 0xFE0F, 0xE0100, 0x180E, 0x3164, 0xE0041, 0x202E} {
		if got := Sanitize("a"+string(r)+"b", 0); got != "ab" {
			t.Errorf("U+%04X survived: %q", r, got)
		}
	}
	for _, r := range []rune{0x1B, 0x85, 0x9B, 0x2028, 0x2029, 0x7F} {
		if got := Sanitize("a"+string(r)+"b", 0); got != "a b" {
			t.Errorf("control U+%04X not replaced: %q", r, got)
		}
	}
	if got := Sanitize("中文 café ✓ 🙂", 0); got != "中文 café ✓ 🙂" {
		t.Errorf("visible text damaged: %q", got)
	}
}
