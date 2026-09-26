package agents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// MCPServer is one configured MCP server. Environment values are never kept,
// only their names; args and URLs are redacted.
type MCPServer struct {
	Client  Kind     `json:"client"`
	Name    string   `json:"name"`
	Source  string   `json:"source"`
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	URL     string   `json:"url,omitempty"`
	EnvKeys []string `json:"env_keys,omitempty"`
}

// Dirs are the per-user roots config files live under.
type Dirs struct {
	Home, AppData, LocalAppData string
	// Remote reports paths that must not be opened (network locations,
	// relative paths). Project folders listed in ~/.claude.json may be UNC
	// paths, and with folder redirection the profile itself can live on a
	// share; reading there would make Windows connect to the server, so such
	// files are skipped (third review, item 17).
	Remote func(string) bool
}

// DirsFromEnv reads the standard Windows locations.
func DirsFromEnv() Dirs {
	home, _ := os.UserHomeDir()
	return Dirs{Home: home, AppData: os.Getenv("APPDATA"), LocalAppData: os.Getenv("LOCALAPPDATA")}
}

type jsonSource struct {
	client Kind
	path   string
	keys   []string // nested key path to the server map
}

// Inventory reads every known MCP client config. Missing files are skipped;
// unreadable or malformed ones are returned as warnings.
func Inventory(d Dirs) (servers []MCPServer, warnings []string) {
	var sources []jsonSource
	remote := func(p string) bool { return d.Remote != nil && d.Remote(p) }
	add := func(c Kind, path string, keys ...string) {
		if path != "" {
			sources = append(sources, jsonSource{c, path, keys})
		}
	}
	j := filepath.Join
	add(ClaudeCode, j(d.Home, ".claude.json"), "mcpServers")
	add(ClaudeCode, j(d.Home, ".mcp.json"), "mcpServers")
	add(ClaudeDesktop, j(d.AppData, "Claude", "claude_desktop_config.json"), "mcpServers")
	// The Store (MSIX) build of Claude Desktop is file-system virtualised: outside
	// the package, its Roaming files live under Packages\Claude_*\LocalCache.
	if remote(j(d.LocalAppData, "Packages")) {
		warnings = append(warnings, "skipped Claude Desktop (Store) config: the local app data folder is not on a local drive (not opened)")
	} else if m, _ := filepath.Glob(j(d.LocalAppData, "Packages", "Claude_*", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json")); len(m) > 0 {
		for _, p := range m {
			add(ClaudeDesktop, p, "mcpServers")
		}
	}
	add(Cursor, j(d.Home, ".cursor", "mcp.json"), "mcpServers")
	add(VSCode, j(d.AppData, "Code", "User", "mcp.json"), "servers")
	add(VSCode, j(d.AppData, "Code", "User", "settings.json"), "mcp", "servers")
	add(Windsurf, j(d.Home, ".codeium", "windsurf", "mcp_config.json"), "mcpServers")
	add(GeminiCLI, j(d.Home, ".gemini", "settings.json"), "mcpServers")
	add(Antigravity, j(d.Home, ".gemini", "antigravity", "mcp_config.json"), "mcpServers")
	add(Kiro, j(d.Home, ".kiro", "settings", "mcp.json"), "mcpServers")

	seen := map[string]bool{}
	for _, s := range sources {
		key := strings.ToLower(s.path) + "|" + strings.Join(s.keys, ".")
		if seen[key] {
			continue
		}
		seen[key] = true
		if remote(s.path) {
			warnings = append(warnings, "skipped a config file that is not on a local drive (not opened): "+s.path)
			continue
		}
		got, projects, err := readJSONSource(s)
		if err != nil {
			if !os.IsNotExist(err) {
				warnings = append(warnings, s.path+": "+err.Error())
			}
			continue
		}
		servers = append(servers, got...)
		// Claude Code keeps per-project servers inside ~/.claude.json and in each
		// project's .mcp.json.
		for _, proj := range projects {
			if remote(proj) {
				warnings = append(warnings, "skipped a project on a network location (not opened): "+proj)
				continue
			}
			p := j(proj, ".mcp.json")
			k := strings.ToLower(p) + "|mcpServers"
			if seen[k] {
				continue
			}
			seen[k] = true
			more, _, err := readJSONSource(jsonSource{ClaudeCode, p, []string{"mcpServers"}})
			if err == nil {
				servers = append(servers, more...)
			}
		}
	}

	codex := j(d.Home, ".codex", "config.toml")
	if remote(codex) {
		warnings = append(warnings, "skipped a config file that is not on a local drive (not opened): "+codex)
	} else if b, err := os.ReadFile(codex); err == nil {
		servers = append(servers, parseCodexTOML(string(b), codex)...)
	} else if !os.IsNotExist(err) {
		warnings = append(warnings, codex+": "+err.Error())
	}
	return servers, warnings
}

type rawServer struct {
	Command   string         `json:"command"`
	Args      []string       `json:"args"`
	Env       map[string]any `json:"env"`
	URL       string         `json:"url"`
	ServerURL string         `json:"serverUrl"`
	HTTPURL   string         `json:"httpUrl"`
}

func readJSONSource(s jsonSource) ([]MCPServer, []string, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(StripJSONC(b), &root); err != nil {
		return nil, nil, err
	}
	var out []MCPServer
	out = append(out, serversAt(root, s.keys, s.client, s.path)...)

	var projects []string
	if s.client == ClaudeCode && strings.EqualFold(filepath.Base(s.path), ".claude.json") {
		var projs map[string]map[string]json.RawMessage
		if raw, ok := root["projects"]; ok && json.Unmarshal(raw, &projs) == nil {
			for dir, p := range projs {
				projects = append(projects, dir)
				out = append(out, serversAt(p, []string{"mcpServers"}, ClaudeCode, s.path+" (project "+dir+")")...)
			}
			slices.Sort(projects)
		}
	}
	return out, projects, nil
}

func serversAt(root map[string]json.RawMessage, keys []string, client Kind, source string) []MCPServer {
	cur := root
	for i, k := range keys {
		raw, ok := cur[k]
		if !ok {
			return nil
		}
		if i == len(keys)-1 {
			var m map[string]rawServer
			if json.Unmarshal(raw, &m) != nil {
				return nil
			}
			var out []MCPServer
			for name, r := range m {
				out = append(out, fromRaw(client, name, source, r))
			}
			slices.SortFunc(out, func(a, b MCPServer) int { return strings.Compare(a.Name, b.Name) })
			return out
		}
		var next map[string]json.RawMessage
		if json.Unmarshal(raw, &next) != nil {
			return nil
		}
		cur = next
	}
	return nil
}

func fromRaw(client Kind, name, source string, r rawServer) MCPServer {
	s := MCPServer{Client: client, Name: name, Source: source, Command: r.Command}
	for _, a := range r.Args {
		s.Args = append(s.Args, Redact(a))
	}
	for _, u := range []string{r.URL, r.ServerURL, r.HTTPURL} {
		if u != "" {
			s.URL = Redact(u)
			break
		}
	}
	for k := range r.Env {
		s.EnvKeys = append(s.EnvKeys, k)
	}
	slices.Sort(s.EnvKeys)
	return s
}

// StripJSONC removes // and /* */ comments and trailing commas so VS Code style
// settings files parse as JSON.
func StripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	// Drop commas followed only by whitespace and a closing bracket.
	res := make([]byte, 0, len(out))
	inStr, esc = false, false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			res = append(res, c)
			continue
		}
		if c == '"' {
			inStr = true
		}
		if c == ',' {
			j := i + 1
			for j < len(out) && strings.ContainsRune(" \t\r\n", rune(out[j])) {
				j++
			}
			if j < len(out) && (out[j] == '}' || out[j] == ']') {
				continue
			}
		}
		res = append(res, c)
	}
	return res
}

// parseCodexTOML extracts [mcp_servers.<name>] tables from Codex's config.toml.
// It understands just enough TOML for that: string values and string arrays.
func parseCodexTOML(src, source string) []MCPServer {
	var out []MCPServer
	var cur *MCPServer
	inEnv := false
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			table := strings.Trim(line, "[] ")
			inEnv = false
			rest, ok := strings.CutPrefix(table, "mcp_servers.")
			if !ok {
				cur = nil
				continue
			}
			name, sub := splitTOMLKey(rest)
			if sub == "env" && cur != nil && cur.Name == name {
				inEnv = true
				continue
			}
			if sub != "" {
				cur = nil
				continue
			}
			out = append(out, MCPServer{Client: Codex, Name: name, Source: source})
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if inEnv {
			cur.EnvKeys = append(cur.EnvKeys, strings.Trim(key, `"'`))
			continue
		}
		// Multi-line arrays: keep reading until the closing bracket.
		if strings.HasPrefix(val, "[") {
			for !strings.Contains(stripTOMLStrings(val), "]") && i+1 < len(lines) {
				i++
				val += " " + strings.TrimSpace(lines[i])
			}
		}
		switch key {
		case "command":
			cur.Command = tomlString(val)
		case "url":
			cur.URL = Redact(tomlString(val))
		case "args":
			for _, a := range tomlStrings(val) {
				cur.Args = append(cur.Args, Redact(a))
			}
		case "env":
			// Inline table: env = { KEY = "v", ... } — keep keys only.
			for _, part := range strings.Split(strings.Trim(val, "{} "), ",") {
				if k, _, ok := strings.Cut(part, "="); ok {
					cur.EnvKeys = append(cur.EnvKeys, strings.Trim(strings.TrimSpace(k), `"'`))
				}
			}
		}
	}
	for i := range out {
		slices.Sort(out[i].EnvKeys)
	}
	return out
}

// splitTOMLKey splits `name.sub` or `"na.me".sub` into name and remainder.
func splitTOMLKey(s string) (string, string) {
	if strings.HasPrefix(s, `"`) || strings.HasPrefix(s, `'`) {
		q := s[:1]
		if end := strings.Index(s[1:], q); end >= 0 {
			name := s[1 : 1+end]
			return name, strings.TrimPrefix(s[2+end:], ".")
		}
	}
	name, sub, _ := strings.Cut(s, ".")
	return name, sub
}

func tomlString(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '\'' {
		if end := strings.IndexByte(v[1:], '\''); end >= 0 {
			return v[1 : 1+end]
		}
	}
	if len(v) >= 2 && v[0] == '"' {
		var b strings.Builder
		for i := 1; i < len(v); i++ {
			c := v[i]
			if c == '\\' && i+1 < len(v) {
				i++
				switch v[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(v[i])
				}
				continue
			}
			if c == '"' {
				break
			}
			b.WriteByte(c)
		}
		return b.String()
	}
	return v
}

func tomlStrings(v string) []string {
	var out []string
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	for {
		v = strings.TrimLeft(v, " ,\t")
		if v == "" || v[0] == ']' {
			return out
		}
		if v[0] != '"' && v[0] != '\'' {
			return out
		}
		s := tomlString(v)
		out = append(out, s)
		// Skip past the literal we just read.
		q := v[0]
		i := 1
		for i < len(v) {
			if q == '"' && v[i] == '\\' {
				i += 2
				continue
			}
			if v[i] == q {
				break
			}
			i++
		}
		v = v[min(i+1, len(v)):]
	}
}

func stripTOMLStrings(v string) string {
	var b strings.Builder
	var q byte
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case q == 0 && (c == '"' || c == '\''):
			q = c
		case q != 0 && c == '\\' && q == '"':
			i++
		case q != 0 && c == q:
			q = 0
		case q == 0:
			b.WriteByte(c)
		}
	}
	return b.String()
}
