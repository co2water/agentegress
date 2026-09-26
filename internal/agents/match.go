package agents

import (
	"path"
	"regexp"
	"strings"
)

// genericFiles are entry-point names shared by unrelated programs.
var genericFiles = map[string]bool{
	"index.js": true, "index.mjs": true, "index.cjs": true, "index.ts": true, "main.js": true, "main.ts": true,
	"server.js": true, "server.ts": true, "cli.js": true, "app.js": true, "bin.js": true, "start.js": true,
	"main.py": true, "server.py": true, "app.py": true, "__main__.py": true, "run.py": true, "cli.py": true,
	"main.exe": true, "server.exe": true, "app.exe": true, "index.html": true,
}

// commonWords appear as argument values everywhere and identify nothing.
var commonWords = map[string]bool{
	"localhost": true, "false": true, "debug": true, "trace": true, "error": true, "verbose": true, "quiet": true,
	"stdio": true, "stdin": true, "stdout": true, "server": true, "client": true, "local": true, "global": true,
	"production": true, "development": true, "default": true, "config": true, "enable": true, "disable": true,
	"always": true, "never": true, "start": true, "serve": true, "listen": true, "0.0.0.0": true, "127.0.0.1": true,
	"--yes": true, "latest": true, "headless": true, "background": true,
}

var absPath = regexp.MustCompile(`^([a-z]:/|/)`)

var genericDirs = map[string]bool{"dist": true, "build": true, "src": true, "lib": true, "out": true, "bin": true,
	"node_modules": true, "app": true, "server": true, ".": true, "..": true}

// distinctiveDir reports a relative path whose folders name something specific
// ("node_modules/@acme/mcp-x/dist/server.js"), unlike "dist/index.js".
func distinctiveDir(t string) bool {
	parts := strings.Split(t, "/")
	if len(parts) < 2 {
		return false
	}
	for _, d := range parts[:len(parts)-1] {
		if len(d) >= 4 && !genericDirs[d] {
			return true
		}
	}
	return false
}

var versionTag = regexp.MustCompile(`^(v?[0-9][0-9a-z.\-+]*|latest|next|beta|alpha|canary|rc)$`)

var (
	fsPath    = regexp.MustCompile(`^([a-z]:/|/|\./|\.\./|~)`)
	scriptExt = regexp.MustCompile(`\.(js|mjs|cjs|ts|py|exe|jar|dll|cmd|bat|ps1|sh)$`)
)

// Launchers and flags that appear in almost every MCP command line and so say
// nothing about which server it is.
var genericTokens = map[string]bool{
	"npx": true, "npx.cmd": true, "node": true, "node.exe": true, "uvx": true, "uv": true,
	"python": true, "python.exe": true, "python3": true, "py": true, "cmd": true, "cmd.exe": true,
	"/c": true, "docker": true, "run": true, "bun": true, "bunx": true, "deno": true, "pnpm": true,
	"dlx": true, "yarn": true, "java": true, "-jar": true, "powershell": true, "pwsh": true, "stdio": true,
}

var containerTools = map[string]bool{"docker": true, "docker.exe": true, "podman": true, "podman.exe": true}

// Container flags whose value is an environment name, a mount, a port or a
// label: text any process can repeat.
var containerValued = map[string]bool{
	"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true, "--mount": true, "--name": true,
	"--network": true, "--net": true, "-p": true, "--publish": true, "-w": true, "--workdir": true, "-l": true,
	"--label": true, "-u": true, "--user": true, "--entrypoint": true, "--platform": true, "-h": true,
	"--hostname": true, "--add-host": true, "--cap-add": true, "--cap-drop": true, "-m": true, "--memory": true,
	"--cpus": true, "--pull": true,
}

// envName matches an environment variable name or assignment
// ("GITHUB_PERSONAL_ACCESS_TOKEN", "LOG_LEVEL=debug").
var envName = regexp.MustCompile(`^[A-Z][A-Z0-9]*_[A-Z0-9_]*$|^[A-Za-z_][A-Za-z0-9_]*=`)

// tokens returns the distinctive, normalised pieces of a server's command and
// args: package names, script paths and their file names.
//
// Third review, item 13: environment names and, for container launchers,
// flag values and an image's last path segment are not tokens. Any process
// can mention them, and a match gives a process a configured server's name.
func (s MCPServer) tokens() []string {
	var out []string
	container := containerTools[path.Base(strings.ToLower(strings.ReplaceAll(s.Command, `\`, "/")))]
	skip := false
	for _, raw := range append([]string{s.Command}, s.Args...) {
		if skip {
			skip = false
			continue
		}
		trimmed := strings.Trim(raw, `"' `)
		if envName.MatchString(trimmed) {
			continue
		}
		t := strings.ToLower(strings.ReplaceAll(trimmed, `\`, "/"))
		if container && containerValued[t] {
			skip = true
			continue
		}
		if t == "" || strings.HasPrefix(t, "-") || genericTokens[t] || genericTokens[path.Base(t)] {
			continue
		}
		if strings.Contains(t, "***") {
			continue
		}
		// Ports, counts and other short or letterless values ("9443", "true")
		// identify nothing, and any process can mention them — an implant
		// quoting a server's port was labelled as that server.
		if len(t) < 5 || !hasLetter(t) || commonWords[t] {
			continue
		}
		// A filesystem path only identifies the server if it names a script or
		// binary; directory arguments (allowed roots, cwd) appear in unrelated
		// command lines too.
		if fsPath.MatchString(t) && !scriptExt.MatchString(t) {
			continue
		}
		// Drop a version suffix (@scope/pkg@1.2.3, pkg@latest) — only when what
		// follows the @ looks like a version or dist-tag, so
		// "node_modules/@acme/x" is not cut down to "node_modules/".
		if i := strings.LastIndexByte(t, '@'); i > 0 && !fsPath.MatchString(t) && versionTag.MatchString(t[i+1:]) {
			t = t[:i]
		}
		// A generic file name only counts inside an absolute path: a relative
		// "dist/index.js" matched every project with that layout.
		if len(t) >= 4 && !genericFiles[path.Base(t)] || absPath.MatchString(t) && len(t) >= 12 || distinctiveDir(t) {
			out = append(out, t)
		}
		// The file name alone identifies a server only when it is distinctive:
		// "index.js" or "server.py" appear in countless unrelated processes.
		if b := path.Base(t); !container && b != t && len(b) >= 6 && !genericFiles[b] {
			out = append(out, b)
		}
	}
	return out
}

func hasLetter(s string) bool {
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

// MatchServer picks the configured server a process command line belongs to, or
// -1. When several match, a server configured for the process's own agent wins,
// then the longest matching token.
func MatchServer(servers []MCPServer, cmdline string, agent Kind) int {
	c := strings.ToLower(strings.ReplaceAll(cmdline, `\`, "/"))
	best, bestScore := -1, 0
	for i, s := range servers {
		score := 0
		for _, t := range s.tokens() {
			if strings.Contains(c, t) && len(t) > score {
				score = len(t)
			}
		}
		if score == 0 {
			continue
		}
		if s.Client == agent {
			score += 1000
		}
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	return best
}
