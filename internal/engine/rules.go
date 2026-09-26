package engine

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/co2water/agentegress/internal/agents"
	"github.com/co2water/agentegress/internal/collect"
	"github.com/co2water/agentegress/internal/snapshot"
)

func init() {
	Rules = []rule{
		{"A1", ruleA1TempExec},
		{"A2", ruleA2DownloadExec},
		{"A3", ruleA3AgentListener},
		{"A4", ruleA4UnknownPeers},
		{"H1", ruleH1UnsignedTalker},
		{"H2", ruleH2UnsignedListener},
		{"H3", ruleH3Logons},
		{"H4", ruleH4UnsignedAutostart},
		{"H5", ruleH5Firewall},
		{"H6", ruleH6AutostartDownloadExec},
		{"H7", ruleH7RDP},
		{"I1", ruleI1Injection},
	}
}

// ---- shared helpers ----

var (
	tempDir    = regexp.MustCompile(`(?i)\\(temp|tmp|downloads)\\`)
	scriptFile = regexp.MustCompile(`(?i)\.(cmd|bat|ps1|psm1|py|js|mjs|cjs|ts|vbs|sh)$`)
)

type pattern struct {
	label string
	re    *regexp.Regexp
	fn    func(string) bool // used instead of re when set
}

// Download-and-execute idioms. Labels are ours and safe to put in Detail.
var downloadExec = []pattern{
	{label: "PowerShell encoded command", re: regexp.MustCompile(`(?i)\b(powershell|pwsh)\b.*\s[-/]e[a-z]*\s+[a-z0-9+/]{20,}={0,2}(\s|$|")`)},
	{label: "download piped into Invoke-Expression", re: regexp.MustCompile(`(?i)\b(iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|net\.webclient|start-bitstransfer)\b.*(\|\s*(iex|invoke-expression)\b|\b(iex|invoke-expression)\s*\()`)},
	{label: "Invoke-Expression of a download", re: regexp.MustCompile(`(?i)\b(iex|invoke-expression)\s*\(.*\b(downloadstring|irm|iwr|invoke-restmethod|invoke-webrequest)\b`)},
	// Only when the interpreter reads its program from the pipe: "| python -c
	// 'parse json'" just processes data (a false positive seen on a real PC).
	{label: "download piped into a shell", fn: pipedIntoInterpreter},
	{label: "certutil download", re: regexp.MustCompile(`(?i)\bcertutil(\.exe)?\b.*[-/]urlcache`)},
	{label: "bitsadmin transfer", re: regexp.MustCompile(`(?i)\bbitsadmin(\.exe)?\b.*[-/]transfer`)},
	{label: "mshta with a remote or script URL", re: regexp.MustCompile(`(?i)\bmshta(\.exe)?\b\s+["']?(https?:|vbscript:|javascript:)`)},
	{label: "regsvr32 remote scriptlet", re: regexp.MustCompile(`(?i)\bregsvr32(\.exe)?\b.*[-/]i:\s*["']?https?:`)},
	{label: "rundll32 script URL", re: regexp.MustCompile(`(?i)\brundll32(\.exe)?\b.*javascript:`)},
}

func matchAny(ps []pattern, s string) string {
	for _, p := range ps {
		if p.fn != nil && p.fn(s) || p.re != nil && p.re.MatchString(s) {
			return p.label
		}
	}
	return ""
}

var downloadWord = regexp.MustCompile(`(?i)\b(curl|wget)\b`)

// Interpreters a download can be piped into, and the flags that make them take
// their program from an argument instead of the pipe.
var pipeInterpreters = map[string][]string{
	"sh": {"-c"}, "bash": {"-c"}, "zsh": {"-c"}, "dash": {"-c"}, "ksh": {"-c"},
	"python": {"-c", "-m"}, "python3": {"-c", "-m"}, "node": {"-e", "-p", "--eval", "--print"},
	"perl": {"-e", "-E"}, "ruby": {"-e"},
}

// pipedIntoInterpreter reports "curl … | bash" and its variants where the
// interpreter runs what arrives on the pipe: bare, with option flags (-x, -e),
// with redirections, or with "-"/"-s". It does not fire when the interpreter's
// program is an argument ("| python -c '…'") or a script file ("| node
// parse.js"), which only processes the downloaded data (a false positive the
// first review found on a real PC, and whose fix a second review found too narrow).
func pipedIntoInterpreter(cmd string) bool {
	loc := downloadWord.FindStringIndex(cmd)
	if loc == nil {
		return false
	}
	rest := cmd[loc[1]:]
	for {
		i := strings.IndexByte(rest, '|')
		if i < 0 {
			return false
		}
		rest = rest[i+1:]
		if strings.HasPrefix(rest, "|") { // "||" is not a pipe
			rest = rest[1:]
			continue
		}
		toks := strings.Fields(rest)
		if len(toks) > 0 && strings.EqualFold(toks[0], "sudo") {
			toks = toks[1:]
		}
		if len(toks) == 0 {
			continue
		}
		name := strings.ToLower(strings.Trim(toks[0], `"'();`))
		name = strings.TrimSuffix(name[strings.LastIndexAny(name, `/\`)+1:], ".exe")
		inline, ok := pipeInterpreters[name]
		if !ok {
			continue
		}
		if readsPipe(toks[1:], inline) {
			return true
		}
	}
}

func readsPipe(args []string, inline []string) bool {
	for i := 0; i < len(args); i++ {
		t := strings.Trim(args[i], `"'`)
		switch t {
		case ">", ">>", "<", "1>", "2>", "&>", "1>>", "2>>":
			i++ // the redirection target is not a script
			continue
		}
		switch {
		case t == "" || strings.HasPrefix(t, "|") || strings.HasPrefix(t, ";") || strings.HasPrefix(t, "&") || strings.HasPrefix(t, ")"):
			return true // end of this command: program came from the pipe
		case t == "-" || t == "-s" || t == "--":
			return true
		case slices.Contains(inline, strings.ToLower(t)):
			return false
		case strings.HasPrefix(t, "-"), strings.ContainsAny(t, "<>"), t == "2>&1":
			continue // option flags and redirections
		default:
			return false // a script file or other argument
		}
	}
	return true
}

func signedOK(sig *collect.Signature) bool {
	return sig != nil && (sig.Status == collect.SigSigned || sig.Status == collect.SigPackage)
}

func tampered(sig *collect.Signature) bool {
	return sig != nil && sig.Status == collect.SigInvalid && strings.Contains(sig.Detail, "modified")
}

// sigSeverity grades a binary that is not validly signed: a file changed after
// signing is always high; an unsigned file in a user-writable folder is high
// (anyone, including malware running as the user, can drop or replace it);
// unsigned elsewhere or an untrusted chain (common for printer drivers) is medium.
func sigSeverity(sig *collect.Signature, userDir bool) (Severity, bool) {
	return fileSeverity("", sig, userDir)
}

// fileSeverity grades one file. Scripts are almost never signed, so an
// unsigned or unverifiable script in a user-writable folder is medium where an
// executable binary would be high. A file on a network location was not opened
// at all, which is itself unusual for something that runs.
func fileSeverity(path string, sig *collect.Signature, userDir bool) (Severity, bool) {
	script := path != "" && collect.IsScriptFile(path)
	switch {
	case sig == nil || signedOK(sig):
		return 0, false
	case sig.Status == collect.SigRemote,
		sig.Status == collect.SigError && sig.Detail == collect.DetailNotFullPath && !userDir:
		return Medium, true
	case tampered(sig):
		return High, true
	case (sig.Status == collect.SigUnsigned || sig.Status == collect.SigError) && userDir:
		if script {
			return Medium, true
		}
		return High, true
	case sig.Status == collect.SigError:
		return Low, true
	default:
		return Medium, true
	}
}

// subject is one file a verdict can be about.
type subject struct {
	path    string
	sig     *collect.Signature
	userDir bool
	payload bool     // loaded by a host program rather than the program itself
	updated bool     // renamed aside by an updater; the file now in its place is validly signed
	limit   Severity // when set, the highest level an unsigned or unverifiable file reaches
}

// worst picks the subject with the highest severity. A host program and the
// file it loads are both judged (second review: a renamed, unsigned
// "rundll32.exe" hid behind the signed DLL it loaded); ties go to the payload.
func worst(subs []subject) (subject, Severity, bool) {
	var best subject
	top, found := Severity(0), false
	for _, sb := range subs {
		sev, ok := fileSeverity(sb.path, sb.sig, sb.userDir)
		if ok && sb.updated && sev > Medium {
			sev = Medium
		}
		if ok && sb.limit != 0 && sev > sb.limit && !tampered(sb.sig) {
			sev = sb.limit
		}
		if ok && (sev > top || sev == top && sb.payload) {
			best, top, found = sb, sev, true
		}
	}
	return best, top, found
}

func procSubjects(p *snapshot.Proc) []subject {
	out := []subject{{path: p.Path, sig: p.Signature, userDir: p.UserDir}}
	// Third review, item 10: an updater (Claude Code's, seen on a real PC)
	// renames the running program to "x.exe.old.N", which then cannot be
	// read. When the file now at the original path is validly signed, that
	// is an update in progress, not an unverifiable program: noted, not high.
	// A file that reads as unsigned or tampered is still judged in full.
	// Fourth and fifth reviews: any program can be named "x.exe.old.N" and
	// made unreadable, so this applies only to an agent process started under
	// the original file name (by path, with either slash, or by bare name),
	// and it lowers the finding to medium, not below: the command line is
	// chosen by whoever starts the process, so it is a hint, not proof.
	if p.Signature != nil && p.Signature.Status == collect.SigError && p.UpdatedTo != "" && signedOK(p.UpdatedToSignature) &&
		p.Agent != "" && exeName(collect.ExecutablePath(p.Cmdline)) == exeName(p.UpdatedTo) {
		out[0].updated = true
	}
	// A developer interpreter's script says little by its signature (scripts
	// are almost never signed; every npx or python MCP server would be
	// flagged). Binary payloads — DLLs, executables, disguised files — and
	// scripts run by Windows Script Host or mshta are judged; fileSeverity
	// caps an unsigned script at medium.
	if p.Payload != "" && (!collect.IsScriptFile(p.Payload) || collect.JudgeScriptPayload(p.Path)) {
		out = append(out, subject{path: p.Payload, sig: p.PayloadSignature, userDir: p.PayloadUserDir, payload: true})
	}
	// Item 11: an MCP server the user configured, matched by its command
	// line, commonly runs on an unsigned runtime the package tool downloaded
	// (uv-managed Python, a venv launcher). That is worth a look but is not the
	// high level kept for an unknown unsigned binary. Tampered files stay high.
	// Fourth review: a command-line match is only a token match, so the cap
	// covers only the program itself, and only a language runtime or a file
	// under uv's own folders — never a payload, never an arbitrary binary.
	// Fifth review: anchored to uv's own folders; a language runtime found
	// elsewhere (node, official Python builds) is normally signed anyway.
	if p.MCP != "" && p.MCP != "?" && underUV(p.Path) {
		out[0].limit = Medium
	}
	return out
}

// underUV reports a path inside uv's managed Python or tool environments:
// %APPDATA%\uv\python\… and %LOCALAPPDATA%\uv\cache\…\Scripts\x.exe.
func underUV(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	return strings.Contains(p, `\appdata\roaming\uv\`) || strings.Contains(p, `\appdata\local\uv\`)
}

// exeName is the lower-case file name of a program, with ".exe" added to a
// bare name ("claude" → "claude.exe").
func exeName(path string) string {
	b := strings.ToLower(path[strings.LastIndexAny(path, `\/`)+1:])
	if b != "" && !strings.Contains(b, ".") {
		b += ".exe"
	}
	return b
}

func autostartSubjects(a snapshot.Autostart) []subject {
	out := []subject{{path: a.Target, sig: a.Signature, userDir: a.UserDir, payload: a.Host != ""}}
	if a.Host != "" {
		out = append(out, subject{path: a.Host, sig: a.HostSignature, userDir: a.HostUserDir})
	}
	return out
}

// whatRuns names the verified subject. The host name comes from our fixed list
// only when the host is a real protected system program; otherwise the text
// stays generic, because a file name is host-controlled.
func whatRuns(p *snapshot.Proc, sb subject) string {
	if sb.payload && collect.ProtectedSystemPath(p.Path) {
		return "the file it runs (loaded by the Windows program " + strings.ToLower(filepath.Base(p.Path)) + ")"
	}
	if sb.payload {
		return "the file it runs"
	}
	return "the binary"
}

func updatedNote(sb subject) string {
	if !sb.updated {
		return ""
	}
	return " An update renamed this program's file aside; the file now at its original path is validly signed, so this is most likely a program that has not restarted since updating."
}

func sigWords(sig *collect.Signature) string {
	switch {
	case sig == nil:
		return "not checked"
	case tampered(sig):
		return "modified after it was signed"
	case sig.Status == collect.SigInvalid:
		return "signed with a certificate chain Windows does not trust"
	case sig.Status == collect.SigUnsigned:
		return "not signed"
	case sig.Status == collect.SigError:
		if sig.Detail != "" {
			return "impossible to verify (" + sig.Detail + ")" // Detail is our own text
		}
		return "impossible to verify"
	case sig.Status == collect.SigRemote:
		return "on a network location, so it was not opened or verified"
	}
	return "signed"
}

func agentOf(p *snapshot.Proc) string {
	if p.Owner != "" {
		return string(p.Owner)
	}
	return "an AI agent"
}

// ---- A: agent-tree rules ----

func ruleA1TempExec(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for _, p := range s.Procs {
		if p.Root == 0 || p.PID == p.Root { // item 8: a nested "agent" is checked like any child
			continue
		}
		var inTemp []subject
		subs := []subject{{path: p.Path, sig: p.Signature, userDir: p.UserDir}}
		if p.Payload != "" { // scripts included: running one from Temp is what A1 is about
			subs = append(subs, subject{path: p.Payload, sig: p.PayloadSignature, userDir: p.PayloadUserDir, payload: true})
		}
		for _, sb := range subs {
			if tempDir.MatchString(sb.path) {
				inTemp = append(inTemp, sb)
			}
		}
		if len(inTemp) == 0 {
			continue
		}
		sb := inTemp[len(inTemp)-1] // the payload when both qualify
		sev := High
		switch {
		case signedOK(sb.sig):
			sev = Medium
		case scriptFile.MatchString(sb.path):
			// Agents routinely write a script to a scratch folder and run it
			// (seen on a real PC). Scripts are rarely signed, so this is noted,
			// not alarmed; unsigned binaries in Temp stay high.
			sev = Low
		}
		out = append(out, Finding{
			Severity: sev, PID: p.PID,
			Title:    "A program started by an AI agent runs from a temporary or download folder",
			Detail:   fmt.Sprintf("Started under %s (pid %d); %s is %s.", agentOf(p), p.PID, whatRuns(p, sb), sigWords(sb.sig)),
			Evidence: ev("subject", sb.path, "command_line", p.Cmdline),
			file:     sb.path,
		})
	}
	return out
}

func ruleA2DownloadExec(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for _, p := range s.Procs {
		if p.Root == 0 || p.PID == p.Root {
			continue
		}
		if label := matchAny(downloadExec, p.Cmdline); label != "" {
			out = append(out, Finding{
				Severity: High, PID: p.PID,
				Title:    "An AI agent ran a download-and-execute command",
				Detail:   fmt.Sprintf("Pattern: %s. Started under %s (pid %d).", label, agentOf(p), p.PID),
				Evidence: ev("subject", p.Cmdline, "command_line", p.Cmdline, "path", p.Path),
			})
		}
	}
	return out
}

func ruleA3AgentListener(s *snapshot.Snapshot) []Finding {
	byPID := map[uint32][]string{}
	for _, c := range s.Conns {
		if p := s.Procs[c.PID]; c.Exposed && p != nil && p.Root != 0 {
			byPID[c.PID] = append(byPID[c.PID], c.Local)
		}
	}
	var out []Finding
	for pid, addrs := range byPID {
		p := s.Procs[pid]
		sev, what := Medium, "A process started by an AI agent"
		if p.MCP != "" {
			sev, what = High, "An MCP server"
		}
		slices.Sort(addrs)
		out = append(out, Finding{
			Severity: sev, PID: pid, ID: findingID("A3", p.Path+"|"+strings.Join(addrs, ",")),
			Title:    what + " accepts connections from the network",
			Detail:   fmt.Sprintf("Listening on %s (pid %d, under %s). Other machines on the network can reach it.", strings.Join(addrs, ", "), pid, agentOf(p)),
			Evidence: ev("subject", p.Path, "command_line", p.Cmdline, "mcp_server", p.MCP),
			file:     p.Path,
		})
	}
	return out
}

// ruleA4UnknownPeers reports agent-tree connections to addresses no provider
// list or DNS cache entry explains. Non-web ports are medium, web ports info.
func ruleA4UnknownPeers(s *snapshot.Snapshot) []Finding {
	type acc struct {
		web, other []string
		hosts      []string
	}
	byPID := map[uint32]*acc{}
	for _, c := range s.Conns {
		p := s.Procs[c.PID]
		if !c.External || p == nil || p.Root == 0 || c.Org != "" || len(c.Hosts) > 0 {
			continue
		}
		a := byPID[c.PID]
		if a == nil {
			a = &acc{}
			byPID[c.PID] = a
		}
		if strings.HasSuffix(c.Remote, ":443") || strings.HasSuffix(c.Remote, ":80") {
			a.web = append(a.web, c.Remote)
		} else {
			a.other = append(a.other, c.Remote)
		}
	}
	var out []Finding
	for pid, a := range byPID {
		p := s.Procs[pid]
		sev, peers := Info, a.web
		title := "An AI agent process talks to a server we cannot identify"
		if len(a.other) > 0 {
			sev, peers = Medium, a.other
			title = "An AI agent process talks to an unidentified server on a non-web port"
		}
		slices.Sort(peers)
		peers = slices.Compact(peers)
		// The ID covers the peers: acknowledging one unknown server must not
		// hide the next one this program talks to.
		out = append(out, Finding{
			Severity: sev, PID: pid, Title: title, ID: findingID("A4", p.Path+"|"+strings.Join(peers, ",")),
			Detail: fmt.Sprintf("%s (pid %d, under %s) is connected to %s, which no bundled provider range or cached DNS name explains.",
				"The process", pid, agentOf(p), strings.Join(peers[:min(5, len(peers))], ", ")),
			Evidence: ev("subject", p.Path, "process", p.Name),
			file:     p.Path,
		})
	}
	return out
}

// ---- H: host rules ----

func ruleH1UnsignedTalker(s *snapshot.Snapshot) []Finding {
	peers := map[uint32][]string{}
	for _, c := range s.Conns {
		if c.External {
			label := c.Remote
			if c.Org != "" {
				label += " (" + c.Org + ")"
			}
			peers[c.PID] = append(peers[c.PID], label)
		}
	}
	var out []Finding
	for pid, list := range peers {
		p := s.Procs[pid]
		if p == nil {
			continue
		}
		sb, sev, ok := worst(procSubjects(p))
		if !ok {
			continue
		}
		path, sig, userDir := sb.path, sb.sig, sb.userDir
		slices.Sort(list)
		list = slices.Compact(list)
		where := ""
		if userDir {
			where = " It lives in a folder any program running as you can write to."
		}
		where += updatedNote(sb)
		out = append(out, Finding{
			Severity: sev, PID: pid,
			Title:    "A program that is not validly signed is talking to the internet",
			Detail:   fmt.Sprintf("pid %d: %s is %s; connected to %s.%s", pid, whatRuns(p, sb), sigWords(sig), strings.Join(list[:min(5, len(list))], ", "), where),
			Evidence: ev("subject", path, "process", p.Name, "command_line", p.Cmdline),
			file:     path,
		})
	}
	return out
}

func ruleH2UnsignedListener(s *snapshot.Snapshot) []Finding {
	addrs := map[uint32][]string{}
	for _, c := range s.Conns {
		if p := s.Procs[c.PID]; c.Exposed && p != nil && p.Root == 0 {
			addrs[c.PID] = append(addrs[c.PID], c.Local)
		}
	}
	var out []Finding
	for pid, list := range addrs {
		p := s.Procs[pid]
		sb, sev, ok := worst(procSubjects(p))
		if !ok {
			continue
		}
		path, sig := sb.path, sb.sig
		slices.Sort(list)
		out = append(out, Finding{
			Severity: sev, PID: pid,
			Title:    "A program that is not validly signed accepts connections from the network",
			Detail:   fmt.Sprintf("pid %d listens on %s; %s is %s.%s", pid, strings.Join(list, ", "), whatRuns(p, sb), sigWords(sig), updatedNote(sb)),
			Evidence: ev("subject", path, "process", p.Name),
			file:     path,
		})
	}
	return out
}

// Failed-logon thresholds over the checked window.
const (
	failedFromInternet = 20
	failedAny          = 50
)

func ruleH3Logons(s *snapshot.Snapshot) []Finding {
	l := s.Logons
	if !l.Checked {
		return nil
	}
	var out []Finding
	var pubCount, allCount int
	var pubIPs, users []string
	for _, src := range l.Failed {
		allCount += src.Count
		if collect.IsPublicIP(src.IP) {
			pubCount += src.Count
			pubIPs = append(pubIPs, src.IP)
			users = append(users, src.Users...)
		}
	}
	if pubCount >= failedFromInternet {
		sev := Medium
		if s.Host.RDPEnabled {
			sev = High
		}
		out = append(out, Finding{
			Severity: sev, ID: findingID("H3", "failed-public"),
			Title:  "Repeated failed logons from the internet",
			Detail: fmt.Sprintf("%s from %s in the last %d hours. Remote Desktop enabled: %v.", plural(pubCount, "failed logon", "failed logons"), plural(len(pubIPs), "public address", "public addresses"), l.Hours, s.Host.RDPEnabled),
			Evidence: ev("source_addresses", strings.Join(pubIPs[:min(10, len(pubIPs))], ", "),
				"user_names_tried", strings.Join(users[:min(10, len(users))], ", ")),
		})
	} else if allCount >= failedAny {
		out = append(out, Finding{
			Severity: Medium, ID: findingID("H3", "failed-any"),
			Title:  "Many failed logons",
			Detail: fmt.Sprintf("%s in the last %d hours, none from public addresses.", plural(allCount, "failed logon", "failed logons"), l.Hours),
		})
	}
	for _, src := range l.RemoteDesk {
		sev, title := Info, "Remote Desktop logon from the local network"
		if collect.IsPublicIP(src.IP) {
			sev, title = High, "Successful Remote Desktop logon from the internet"
		}
		out = append(out, Finding{
			Severity: sev, ID: findingID("H3", "rdp-"+src.IP),
			Title:    title,
			Detail:   fmt.Sprintf("%s in the last %d hours.", plural(src.Count, "logon", "logons"), l.Hours),
			Evidence: ev("source_address", src.IP, "user_names", strings.Join(src.Users, ", ")),
		})
	}
	return out
}

func ruleH4UnsignedAutostart(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for _, a := range s.Autostarts {
		if a.Disabled {
			continue
		}
		sb, sev, ok := worst(autostartSubjects(a))
		if !ok {
			continue
		}
		where := ""
		if sb.userDir {
			where = " It is in a folder any program running as you can write to."
		}
		what := "the program"
		if a.Host != "" && sb.payload {
			what = "the file its host program loads"
		} else if a.Host != "" {
			what = "the host program that loads it"
		}
		out = append(out, Finding{
			Severity: sev,
			Title:    "A program that is not validly signed starts automatically",
			Detail:   fmt.Sprintf("Started by a %s entry (%s scope); %s is %s.%s", kindWords(a.Kind), a.Scope, what, sigWords(sb.sig), where),
			Evidence: ev("subject", sb.path, "entry_name", a.Name, "command", a.Command, "location", a.Location),
			file:     sb.path,
		})
	}
	return out
}

func kindWords(k string) string {
	switch k {
	case "run-key":
		return "Run registry key"
	case "startup-folder":
		return "Startup folder"
	case "scheduled-task":
		return "scheduled task"
	case "service":
		return "Windows service"
	case "winlogon":
		return "Winlogon (non-default value)"
	}
	return "autostart"
}

func ruleH5Firewall(s *snapshot.Snapshot) []Finding {
	if len(s.Host.FirewallDisabled) == 0 {
		return nil
	}
	return []Finding{{
		Severity: Medium, ID: findingID("H5", "firewall"),
		Title:  "Windows Firewall is turned off",
		Detail: fmt.Sprintf("Disabled for profile(s): %s. If another security product manages the firewall this can be expected.", strings.Join(s.Host.FirewallDisabled, ", ")),
	}}
}

func ruleH6AutostartDownloadExec(s *snapshot.Snapshot) []Finding {
	var out []Finding
	for _, a := range s.Autostarts {
		if a.Disabled {
			continue
		}
		if label := matchAny(downloadExec, a.Command); label != "" {
			out = append(out, Finding{
				Severity: High,
				// Third review, item 14: the ID covers the command, so an
				// acknowledged entry that is later rewritten is reported again.
				ID:       findingID("H6", a.Location+"|"+a.Name+"|"+a.Command),
				Title:    "Something that starts automatically downloads and runs code",
				Detail:   fmt.Sprintf("Pattern: %s, in a %s entry.", label, kindWords(a.Kind)),
				Evidence: ev("subject", a.Location+"|"+a.Name, "command", a.Command, "entry_name", a.Name),
			})
		}
	}
	return out
}

func ruleH7RDP(s *snapshot.Snapshot) []Finding {
	if !s.Host.RDPEnabled {
		return nil
	}
	return []Finding{{
		Severity: Info, ID: findingID("H7", "rdp"),
		Title:  "Remote Desktop is enabled",
		Detail: "Remote Desktop accepts connections. If you do not use it, turning it off removes a common attack path.",
	}}
}

// ---- I: text that tries to talk to an AI ----

var injection = []pattern{
	{label: "instruction override", re: regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all|any|your)\b[^.\n]{0,20}\b(instructions?|prompts?|rules|messages|context)\b`)},
	{label: "chat role marker", re: regexp.MustCompile(`\b(SYSTEM|ASSISTANT)\s*:|<\|im_(start|end)\|>|\[/?INST\]|<</?SYS>>|</?(system|assistant)>`)},
	{label: "persona assignment", re: regexp.MustCompile(`(?i)\byou are (now )?(a |an |the )?(ai|assistant|language model|llm|chatbot|security (tool|analyst|scanner))\b`)},
	{label: "verdict steering", re: regexp.MustCompile(`(?i)\b(report|mark|classify|treat|declare)\b[^.\n]{0,40}\bas (clean|safe|benign|trusted|legitimate|harmless|not malicious)\b`)},
	{label: "suppression request", re: regexp.MustCompile(`(?i)\bdo not (report|flag|mention|alert|warn|tell|disclose)\b`)},
	{label: "false authority claim", re: regexp.MustCompile(`(?i)\b(verified|trusted|official|legitimate)\s+(microsoft|windows|anthropic|system)\s+(component|process|binary|file|service)\b`)},
	// Forged tool output: our field names or preamble, with quotes optionally
	// escaped so the text survives inside a command-line argument.
	{label: "forged tool output", re: regexp.MustCompile(`(?i)untrusted_evidence|</?untrusted\b|\bmust_report\b|agentegress result|\\?"verdict\\?"\s*:`)},
}

func hiddenChars(s string) bool {
	for _, r := range s {
		if (r >= 0xE0000 && r <= 0xE007F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return true
		}
	}
	return false
}

// injectionLabel matches after removing invisible characters, so a zero-width
// space cannot split "ignore" into two harmless halves.
func injectionLabel(s string) string {
	if hiddenChars(s) {
		return "hidden Unicode characters"
	}
	clean := agents.StripInvisible(s)
	label := matchAny(injection, clean)
	if label != "" && clean != s {
		return label + " split with invisible characters"
	}
	if label != "" {
		return label
	}
	// Look-alike letters (Cyrillic "і", full-width "ｉ") spell the same words.
	if skel := agents.Skeleton(clean); skel != clean {
		if label = matchAny(injection, skel); label != "" {
			return label + " written with look-alike letters"
		}
	}
	return ""
}

// agentShells run the commands an AI agent issues on the user's behalf. Text
// aimed at an AI in their command lines is usually the user's own work on AI
// tooling (it was, in both reviews of this project), so it is reported, but
// below the critical level reserved for text planted elsewhere.
var agentShells = map[string]bool{
	"bash.exe": true, "sh.exe": true, "zsh.exe": true, "cmd.exe": true, "powershell.exe": true, "pwsh.exe": true,
	"python.exe": true, "python3.exe": true, "py.exe": true, "node.exe": true, "bun.exe": true, "git.exe": true,
}

// agentOwnCommand reports a process that is plausibly a command the agent
// itself issued: a validly signed shell or interpreter, started by an
// agent process, that is not an MCP server.
//
// Fourth review: Claude Code's Bash commands on Windows run through Git's
// bin\bash.exe launcher, which starts usr\bin\bash.exe, so the shell can be a
// grandchild. Only that shape (a signed bash started by a signed bash the
// agent started) is allowed; anything a script starts further down stays
// critical (second review: node under "cmd /c build.cmd").
func agentOwnCommand(s *snapshot.Snapshot, p *snapshot.Proc) bool {
	ownShell := func(q *snapshot.Proc) bool {
		return q.Agent == "" && q.MCP == "" && agentShells[strings.ToLower(q.Name)] && signedOK(q.Signature)
	}
	parent := s.Procs[p.Parent]
	if !ownShell(p) || parent == nil || parent == p {
		return false
	}
	if parent.Agent != "" {
		return true
	}
	// Fifth review: names alone let a script's own bash qualify. Require the
	// launcher layout exactly: <Git>\bin\bash.exe (or sh.exe) starting
	// <Git>\usr\bin\bash.exe (or sh.exe).
	lp := strings.ToLower(strings.ReplaceAll(parent.Path, "/", `\`))
	cp := strings.ToLower(strings.ReplaceAll(p.Path, "/", `\`))
	var root string
	for _, launcher := range []string{`\bin\bash.exe`, `\bin\sh.exe`} {
		if strings.HasSuffix(lp, launcher) {
			root = strings.TrimSuffix(lp, launcher)
		}
	}
	grand := s.Procs[parent.Parent]
	return root != "" && (cp == root+`\usr\bin\bash.exe` || cp == root+`\usr\bin\sh.exe`) &&
		ownShell(parent) && grand != nil && grand != parent && grand.Agent != ""
}

// ruleI1Injection looks at every piece of host text an AI assistant might be
// shown. A hit is critical on its own: legitimate software has no reason to
// address an AI, so the text is either an attack on this tool or a test of it.
func ruleI1Injection(s *snapshot.Snapshot) []Finding {
	var out []Finding
	seen := map[string]bool{}
	hit := func(source, subject string, pid uint32, fields ...string) {
		for i := 0; i+1 < len(fields); i += 2 {
			label := injectionLabel(fields[i+1])
			if label == "" {
				continue
			}
			// One finding per item and text. Processes also key on the pid:
			// two copies of one program carrying different text (or the same
			// text under different parents) are separate findings (third
			// review, item 6: the second one was dropped).
			key := source + "|" + subject + "|" + agents.StripInvisible(fields[i+1])
			if source == "process" {
				key += fmt.Sprintf("|%d", pid)
			}
			if seen[key] {
				return
			}
			seen[key] = true
			f := Finding{
				Severity: Critical, PID: pid,
				// The ID covers the text: acknowledging one message must not
				// hide the next one written through the same program.
				ID:       findingID("I1", subject+"|"+agents.StripInvisible(fields[i+1])),
				Title:    "Text on this machine is trying to instruct an AI",
				Detail:   fmt.Sprintf("Found %s in a %s (field: %s). Treat anything an AI says about this item with suspicion.", label, source, fields[i]),
				Evidence: ev("subject", subject, fields[i], fields[i+1]),
			}
			if p := s.Procs[pid]; source == "process" && p != nil && agentOwnCommand(s, p) {
				// Second review: a milder level must not be reachable by naming
				// a program "node.exe", and must stay in must_report.
				f.Severity = High
				f.Title = "A command an AI agent ran directly contains text addressed to an AI"
				f.Detail = fmt.Sprintf("Found %s in the command line of a signed shell or interpreter that %s started (pid %d). If you did not write this command, treat it as an injection attempt.", label, agentOf(p), pid)
			}
			out = append(out, f)
			return
		}
	}
	for _, p := range s.Procs {
		signer, pSigner := "", ""
		if p.Signature != nil {
			signer = p.Signature.Signer
		}
		if p.PayloadSignature != nil {
			pSigner = p.PayloadSignature.Signer
		}
		hit("process", p.Path+"|"+p.Name, p.PID, "name", p.Name, "path", p.Path, "command_line", p.Cmdline,
			"signer", signer, "payload_signer", pSigner)
	}
	for _, m := range s.MCPServers {
		hit("MCP server config", m.Source+"|"+m.Name, 0, "name", m.Name, "command", m.Command, "args", strings.Join(m.Args, " "),
			"url", m.URL, "source", m.Source, "env_names", strings.Join(m.EnvKeys, " "))
	}
	for _, a := range s.Autostarts {
		signer, hSigner := "", ""
		if a.Signature != nil {
			signer = a.Signature.Signer
		}
		if a.HostSignature != nil {
			hSigner = a.HostSignature.Signer
		}
		hit("autostart entry", a.Location+"|"+a.Name, 0, "entry_name", a.Name, "command", a.Command,
			"location", a.Location, "target", a.Target, "signer", signer, "host", a.Host, "host_signer", hSigner)
	}
	for _, c := range s.Conns {
		for _, h := range c.Hosts {
			hit("DNS name", h, c.PID, "host", h)
		}
	}
	for _, list := range [][]collect.LogonSource{s.Logons.Failed, s.Logons.RemoteDesk} {
		for _, src := range list {
			for _, u := range src.Users {
				hit("logon account name", src.IP+"|"+u, 0, "user_name", u)
			}
		}
	}
	return out
}
