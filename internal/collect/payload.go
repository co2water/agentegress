package collect

import (
	"os"
	"regexp"
	"strings"
)

// hostKind says how a program that runs other code takes its payload.
type hostKind int

const (
	hkNone hostKind = iota
	hkRundll32
	hkRegsvr32
	hkScriptHost // wscript, cscript
	hkMshta
	hkPowerShell
	hkCmd
	hkMsiexec
	hkInterpreter // node, python, bun, deno: first non-flag argument is the script
	hkJava        // java/javaw -jar x.jar
	hkConhost     // conhost [--headless] [--width N] program ...
)

var hostKinds = map[string]hostKind{
	"rundll32.exe": hkRundll32, "regsvr32.exe": hkRegsvr32,
	"wscript.exe": hkScriptHost, "cscript.exe": hkScriptHost, "mshta.exe": hkMshta,
	"powershell.exe": hkPowerShell, "pwsh.exe": hkPowerShell, "cmd.exe": hkCmd, "msiexec.exe": hkMsiexec,
	"node.exe": hkInterpreter, "python.exe": hkInterpreter, "pythonw.exe": hkInterpreter, "python3.exe": hkInterpreter,
	"py.exe": hkInterpreter, "pyw.exe": hkInterpreter, "bun.exe": hkInterpreter, "deno.exe": hkInterpreter,
	"java.exe": hkJava, "javaw.exe": hkJava, "conhost.exe": hkConhost,
}

// Flags after which an interpreter's program comes from the argument, not a
// file: "python -c '...'", "node -e '...'", "python -m module".
var inlineFlags = map[string]bool{"-c": true, "-e": true, "-m": true, "-p": true, "--eval": true, "--print": true}

// cmd.exe built-ins: "cmd /c dir C:\x\setup.exe" runs nothing from disk.
var cmdBuiltins = map[string]bool{
	"assoc": true, "break": true, "cd": true, "chdir": true, "cls": true, "color": true, "copy": true, "date": true,
	"del": true, "dir": true, "echo": true, "endlocal": true, "erase": true, "exit": true, "for": true, "ftype": true,
	"goto": true, "if": true, "md": true, "mkdir": true, "mklink": true, "move": true, "path": true, "pause": true,
	"popd": true, "prompt": true, "pushd": true, "rd": true, "rem": true, "ren": true, "rename": true, "rmdir": true,
	"set": true, "setlocal": true, "shift": true, "time": true, "title": true, "type": true, "ver": true,
	"verify": true, "vol": true,
}

var scriptExt = regexp.MustCompile(`(?i)\.(cmd|bat|ps1|psm1|py|pyw|js|jse|mjs|cjs|ts|vbs|vbe|wsf|hta|sct|sh|jar)$`)

// IsScriptFile reports whether path names a script or archive that
// Authenticode normally does not cover: such files are practically never
// signed, so "unsigned" says little about them.
func IsScriptFile(path string) bool { return scriptExt.MatchString(path) }

// IsScriptHost reports whether the program named by path runs other code
// given on its command line. It looks at the file name only; callers must
// still judge the host binary itself (a renamed fake "rundll32.exe" in a user
// folder is unsigned and must be reported as such).
func IsScriptHost(path string) bool { return hostKinds[hostName(path)] != hkNone }

// hostName is the lower-case file name of a program, with ".exe" added when a
// bare name ("wscript", found through PATH) has no extension.
func hostName(p string) string {
	b := strings.ToLower(filepathBase(p))
	if !strings.Contains(b, ".") {
		b += ".exe"
	}
	return b
}

// JudgeScriptPayload reports whether a script run by this host should be
// judged like a program. Windows Script Host, mshta and regsvr32/rundll32
// scriptlets are rare in development and common in malware, so an unsigned
// script they run from a user-writable folder is worth a look (third review,
// item 3). Developer interpreters (node, python, PowerShell, cmd) are not:
// every npx or uvx MCP server would be flagged for running an unsigned script.
func JudgeScriptPayload(host string) bool {
	switch hostKinds[hostName(host)] {
	case hkScriptHost, hkMshta, hkRegsvr32, hkRundll32:
		return true
	}
	return false
}

// ResolveTarget returns the file an autostart command really runs and, when
// that file is loaded by a host program, the host. Both must be judged.
func ResolveTarget(cmd string) (target, host string) {
	exe := ResolveBare(ExecutablePath(cmd))
	if p := Payload(cmd, exe); p != "" {
		return p, exe
	}
	return exe, ""
}

// Payload returns the file a host program is told to run, or "" when there
// is none (inline code, URLs, built-ins) or host is not a host program.
// Files inside protected system folders (shell32.dll in "rundll32
// shell32.dll,Control_RunDLL x.cpl", wscript.exe in "cmd /c wscript x.js") are
// skipped in favour of the next candidate, because the attacker's file is the
// one outside them.
func Payload(cmd, host string) string {
	cands := payloadCandidates(argsAfter(ExpandEnv(cmd), host), hostName(host), 0)
	for _, c := range cands {
		if !ProtectedSystemPath(c) {
			return c
		}
	}
	return ""
}

func payloadCandidates(args []string, host string, depth int) []string {
	if depth > 3 {
		return nil
	}
	var out []string
	add := func(tok string, bare bool) {
		t := unquote(tok)
		if t == "" || isURL(t) || strings.HasPrefix(t, "-") || strings.HasPrefix(t, "/") && !strings.Contains(t, `\`) {
			return
		}
		if !bare && !strings.ContainsAny(t, `\/`) && !strings.Contains(t, ".") {
			return
		}
		if !strings.ContainsAny(t, `\/`) {
			// A bare name that does not resolve to a system file ("npx" in
			// "cmd /c npx -y …", found through PATH at run time) cannot be
			// verified and would turn every such launch into a finding.
			r := ResolveBare(t)
			if r == t {
				return
			}
			t = r
		}
		if !absolutePath(t) {
			// Relative to the process's working directory, which we do not
			// know: resolving it against ours would verify the wrong file.
			return
		}
		out = append(out, t)
	}
	switch hostKinds[host] {
	case hkRundll32:
		// rundll32 <dll>[,entry] [args]: the DLL (any extension, or none), then
		// file arguments that shell32/url.dll entry points open.
		for i, tok := range args {
			t := unquote(tok)
			if i == 0 {
				if j := strings.IndexByte(t, ','); j >= 0 {
					t = unquote(t[:j])
				}
				add(t, true)
				continue
			}
			if j := strings.IndexByte(t, ','); j >= 0 {
				t = t[j+1:]
				if k := strings.IndexByte(t, ' '); k >= 0 {
					t = t[k+1:]
				}
			}
			add(t, false)
		}
	case hkRegsvr32:
		for _, tok := range args {
			t := unquote(tok)
			if low := strings.ToLower(t); strings.HasPrefix(low, "/i:") {
				add(t[3:], false)
				continue
			}
			add(t, true)
		}
	case hkScriptHost, hkMshta:
		for _, tok := range args {
			t := unquote(tok)
			if strings.HasPrefix(t, "/") { // //B, //E:jscript, /nologo
				continue
			}
			add(t, true)
			break
		}
	case hkPowerShell:
		for i := 0; i < len(args); i++ {
			switch psParam(unquote(args[i])) {
			case psEncoded:
				return out
			case psValued:
				i++
			case psFlag:
			case psFile:
				if i+1 < len(args) {
					add(args[i+1], true)
				}
				return out
			case psCommand:
				nested := commandText(args[i+1:], add, depth) // add() appends to out
				return append(out, nested...)
			default:
				// A positional argument: pwsh treats it as -File, Windows
				// PowerShell as -Command; either way the named file runs.
				nested := commandText(args[i:], add, depth)
				return append(out, nested...)
			}
		}
	case hkCmd:
		for i, tok := range args {
			j := cmdRunSwitch(tok)
			if j < 0 {
				continue
			}
			rest := args[i+1:]
			if tail := tok[j+2:]; tail != "" { // /c"C:\x\a.exe" or /q/cprog
				rest = append([]string{tail}, rest...)
			}
			slashS := strings.Contains(strings.ToLower(tok[:j]), "/s")
			for _, a := range args[:i] {
				if la := strings.ToLower(a); strings.HasPrefix(la, "/") && strings.Contains(la, "/s") {
					slashS = true
				}
			}
			rest = cmdStripQuotes(rest, slashS)
			// start ["title"] [/switches] program ...
			for len(rest) > 0 {
				first := strings.ToLower(unquote(rest[0]))
				switch {
				case first == "call" || first == "start":
					rest = rest[1:]
					if first == "start" && len(rest) > 0 && strings.HasPrefix(rest[0], `"`) && len(rest) > 1 {
						rest = rest[1:] // window title
					}
					for len(rest) > 0 && strings.HasPrefix(rest[0], "/") {
						rest = rest[1:]
					}
					continue
				case cmdBuiltins[first]:
					return out
				}
				break
			}
			if len(rest) == 0 {
				return out
			}
			prog := unquote(rest[0])
			add(prog, true)
			if IsScriptHost(prog) {
				out = append(out, payloadCandidates(rest[1:], hostName(prog), depth+1)...)
			}
			return out
		}
	case hkMsiexec:
		for i, tok := range args {
			low := strings.ToLower(unquote(tok))
			if (low == "/i" || low == "/package" || low == "/a") && i+1 < len(args) {
				add(args[i+1], true)
			}
		}
	case hkInterpreter:
		for _, tok := range args {
			t := unquote(tok)
			if inlineFlags[strings.ToLower(t)] {
				return out
			}
			if strings.HasPrefix(t, "-") {
				continue
			}
			add(t, true)
			break
		}
	case hkJava:
		for i, tok := range args {
			if strings.EqualFold(unquote(tok), "-jar") && i+1 < len(args) {
				add(args[i+1], true)
			}
		}
	case hkConhost:
		for i := 0; i < len(args); i++ {
			low := strings.ToLower(unquote(args[i]))
			switch {
			case conhostValued[low]:
				i++
			case strings.HasPrefix(low, "-"):
			default:
				prog := unquote(args[i])
				if !strings.ContainsAny(prog, `\/`) && ResolveBare(prog) == prog {
					continue // a value of an option we do not know ("--vtmode xterm")
				}
				add(prog, true)
				if IsScriptHost(prog) {
					out = append(out, payloadCandidates(args[i+1:], hostName(prog), depth+1)...)
				}
				return out
			}
		}
	}
	return out
}

var conhostValued = map[string]bool{"--width": true, "--height": true, "--signal": true, "--server": true, "--feature": true, "--vtmode": true}

// absolutePath reports whether p names a file without depending on a current
// directory: a drive path, a UNC path or an NT-namespace path.
func absolutePath(p string) bool {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`) || strings.HasPrefix(p, `\??\`)
}

// cmdRunSwitch returns the index of /c, /k or /r inside a cmd.exe switch
// token ("/c", "/q/c", "/d/c", `/c"C:\x.exe"`), or -1.
func cmdRunSwitch(tok string) int {
	if !strings.HasPrefix(tok, "/") {
		return -1
	}
	low := strings.ToLower(tok)
	best := -1
	for _, sw := range []string{"/c", "/k", "/r"} {
		if j := strings.Index(low, sw); j >= 0 && (best < 0 || j < best) {
			best = j
		}
	}
	// Everything before the switch must itself be switches ("/q", "/d",
	// "/e:on"), so "/usr/bin/cat" is not read as "/c" + "at" (fourth review:
	// "/cC:\x\a.exe" was rejected outright).
	if best < 0 || best+2 > len(tok) || !cmdSwitches.MatchString(low[:best]) {
		return -1
	}
	return best
}

var cmdSwitches = regexp.MustCompile(`^(/[a-z](:[a-z0-9]+)?)*$`)

// cmdStripQuotes applies cmd.exe's rule for the text after /c. Without /s,
// exactly two quotes around the name of a program with no special characters
// between them are kept (`"C:\Program Files\App\start.bat"`, or the same
// followed by arguments). Otherwise, when the text starts with a quote, the
// first and the last quote are removed (`"C:\x\a.exe --flag"`,
// `""C:\a b\x.exe" arg"`). Whether the quoted name is an existing program is
// looked up on local drives only (localFile); if neither reading names a
// program, the quoted name is judged when it has an executable extension.
func cmdStripQuotes(rest []string, slashS bool) []string {
	j := strings.Join(rest, " ")
	n := strings.Count(j, `"`)
	if !strings.HasPrefix(j, `"`) || n < 2 {
		return rest
	}
	last := strings.LastIndexByte(j, '"')
	stripped := splitArgs(j[1:last] + j[last+1:])
	if n == 2 && !slashS {
		inner := strings.TrimSpace(j[1 : 1+strings.IndexByte(j[1:], '"')])
		// cmd.exe's rule: the quotes stay when the text between them has a
		// space, no special characters, and names an existing file.
		if strings.Contains(inner, " ") && !strings.ContainsAny(inner, "&<>()@^|") && localProgram(inner) {
			return rest
		}
		// Fifth review: a stale entry whose program was uninstalled, or one
		// cmd itself cannot run (`"C:\Program Files (x86)\x.exe"`), would be
		// judged as "C:\Program". When the stripped reading's first word is
		// no program at all, judge the quoted program instead.
		if len(stripped) > 0 {
			first := unquote(stripped[0])
			if !executable.MatchString(first) && !programFound(first) && executable.MatchString(inner) {
				return rest
			}
		}
	}
	return stripped
}

// localFile reports an existing file on a local drive. Network paths are
// never looked up, and a link is not followed (sixth review: os.Stat followed
// a file symlink to a share, which would open an SMB connection); a link
// counts as existing and is judged later by VerifyFile's link rules.
func localFile(p string) bool {
	if IsRemotePath(p) {
		return false
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !fi.IsDir()
}

// pathExt is cmd.exe's default PATHEXT: the extensions it tries for a
// program named without one.
var pathExt = []string{".com", ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc"}

// localProgram reports a local file named p, or p plus a PATHEXT extension.
func localProgram(p string) bool {
	if localFile(p) {
		return true
	}
	for _, ext := range pathExt {
		if localFile(p + ext) {
			return true
		}
	}
	return false
}

// programFound reports whether cmd.exe could run tok as a program: a bare
// name (found through PATH at run time, or a built-in), a network path (not
// looked up), or a local file with or without a PATHEXT extension.
func programFound(tok string) bool {
	if !strings.ContainsAny(tok, `\/`) || IsRemotePath(tok) {
		return true
	}
	return localProgram(tok)
}

type psKind int

const (
	psPositional psKind = iota
	psFlag
	psValued
	psFile
	psCommand
	psEncoded
)

var psNames = []struct {
	name string
	kind psKind
}{
	{"file", psFile}, {"command", psCommand}, {"encodedcommand", psEncoded}, {"encodedarguments", psValued},
	{"executionpolicy", psValued}, {"windowstyle", psValued}, {"version", psValued}, {"inputformat", psValued},
	{"outputformat", psValued}, {"configurationname", psValued}, {"configurationfile", psValued},
	{"psconsolefile", psValued}, {"workingdirectory", psValued}, {"settingsfile", psValued}, {"custompipename", psValued},
}

// psParam classifies a powershell.exe / pwsh.exe argument. Parameter names
// may be shortened to a prefix; the documented short aliases are listed.
func psParam(tok string) psKind {
	if !strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "/") {
		return psPositional
	}
	n := strings.ToLower(strings.TrimLeft(tok, "-/"))
	if strings.Contains(n, ":") { // -ExecutionPolicy:Bypass carries its value
		return psFlag
	}
	switch n {
	case "":
		return psFlag
	case "e", "ec", "enc":
		return psEncoded
	case "c":
		return psCommand
	case "f":
		return psFile
	case "ep", "ex", "exec", "w", "v", "o", "if", "of", "wd", "inp":
		return psValued
	}
	for _, p := range psNames {
		if len(n) >= 2 && strings.HasPrefix(p.name, n) {
			return p.kind
		}
	}
	return psFlag
}

// commandText finds the file a PowerShell command runs when the command
// starts with a path: `C:\x\a.exe`, `& 'C:\x\a.ps1' -y`, `. 'C:\x\b.ps1'`.
// Standard input ("-Command -") and script blocks name no file.
func commandText(args []string, add func(string, bool), depth int) []string {
	text := strings.TrimSpace(strings.Join(args, " "))
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		text = strings.TrimSpace(text[1 : len(text)-1]) // one pair only: the command may quote inside
	}
	if text == "" || text == "-" {
		return nil
	}
	for _, op := range []string{"& ", ". "} {
		text = strings.TrimSpace(strings.TrimPrefix(text, op))
	}
	var first, rest string
	if text != "" && (text[0] == '\'' || text[0] == '"') {
		k := strings.IndexByte(text[1:], text[0])
		if k < 0 {
			return nil
		}
		first, rest = text[1:k+1], text[k+2:]
	} else {
		k := strings.IndexAny(text, " ;|")
		if k < 0 {
			k = len(text)
		}
		first, rest = text[:k], text[k:]
	}
	if first == "" || strings.HasPrefix(first, "{") {
		return nil
	}
	add(first, false)
	if IsScriptHost(first) {
		return payloadCandidates(splitArgs(strings.TrimSpace(rest)), hostName(first), depth+1)
	}
	return nil
}

// argsAfter splits the command line and drops everything up to and including
// the host program itself.
func argsAfter(cmd, host string) []string {
	args := splitArgs(strings.TrimSpace(cmd))
	base := strings.ToLower(filepathBase(host))
	for i, a := range args {
		b := strings.ToLower(filepathBase(unquote(a)))
		if b == base || b+".exe" == base {
			return args[i+1:]
		}
	}
	if len(args) > 0 {
		return args[1:]
	}
	return nil
}

func isURL(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "://") || strings.HasPrefix(l, "javascript:") || strings.HasPrefix(l, "vbscript:") || strings.HasPrefix(l, "about:")
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"'`) }

func filepathBase(p string) string {
	i := strings.LastIndexAny(p, `\/`)
	return p[i+1:]
}

// splitArgs splits on spaces outside double quotes.
func splitArgs(s string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			b.WriteRune(r)
		case r == ' ' && !inQ:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}
