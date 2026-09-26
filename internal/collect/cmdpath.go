package collect

import (
	"os"
	"regexp"
	"strings"
)

var (
	envVar     = regexp.MustCompile(`%([A-Za-z0-9_()]+)%`)
	executable = regexp.MustCompile(`(?i)\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|dll|sys|cpl|msi)$`)
)

// ExpandEnv expands %VAR% references using the current environment, leaving
// unknown variables untouched.
func ExpandEnv(s string) string {
	return envVar.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := os.LookupEnv(m[1 : len(m)-1]); ok {
			return v
		}
		return m
	})
}

// userWritableUnderSystem32 lists folders inside System32/SysWOW64 that a
// standard user can write to (well-known application-control bypass paths).
var userWritableUnderSystem32 = []string{
	`\spool\drivers\color\`, `\spool\printers\`, `\spool\servers\`, `\tasks\`, `\tasks_migrated\`,
	`\microsoft\crypto\rsa\machinekeys\`, `\com\dmp\`, `\fxstmp\`, `\tracing\`, `\logfiles\`,
}

// ProtectedSystemPath reports whether path is inside System32 or SysWOW64
// and outside their user-writable subfolders: only administrators or
// TrustedInstaller can place or replace files there.
//
// The path is made canonical first (review finding: "System32\.\spool\...",
// doubled separators, trailing dots and 8.3 short names all reached the
// writable folders while matching the protected prefix).
func ProtectedSystemPath(path string) bool {
	root := strings.ToLower(strings.TrimRight(os.Getenv("SystemRoot"), `\`))
	p, ok := canonicalPath(path)
	if root == "" || !ok {
		return false
	}
	for _, dir := range []string{root + `\system32\`, root + `\syswow64\`} {
		if !strings.HasPrefix(p, dir) {
			continue
		}
		rest := p[len(dir)-1:] + `\`
		for _, w := range userWritableUnderSystem32 {
			if strings.HasPrefix(rest, w) {
				return false
			}
		}
		return true
	}
	return false
}

// userWritableUnderWindows lists folders inside %SystemRoot% (outside
// System32/SysWOW64) that a standard user can write to.
var userWritableUnderWindows = []string{
	`\temp\`, `\tasks\`, `\tracing\`, `\registration\crmlog\`, `\debug\wia\`,
	`\pla\reports\`, `\pla\rules\`, `\pla\templates\`,
}

// AdminOnlyPath reports whether path is in a folder only administrators can
// write to: %SystemRoot% (minus its user-writable subfolders) and the
// Program Files folders. Any other folder — the user profile, ProgramData,
// C:\tools, a second drive — is treated as user-writable, because its
// permissions are unknown and commonly let any user add files (third review:
// "C:\tools\x.exe" was graded as if an administrator had installed it).
func AdminOnlyPath(path string) bool {
	p, ok := canonicalPath(path)
	if !ok {
		return false
	}
	if ProtectedSystemPath(p) {
		return true
	}
	if root := strings.ToLower(strings.TrimRight(os.Getenv("SystemRoot"), `\`)); root != "" && strings.HasPrefix(p, root+`\`) {
		rest := p[len(root):]
		for _, dir := range []string{`\system32\`, `\syswow64\`} {
			if strings.HasPrefix(rest, dir) {
				return false // System32's writable subfolders; the rest was handled above
			}
		}
		for _, w := range userWritableUnderWindows {
			if strings.HasPrefix(rest, w) {
				return false
			}
		}
		return true
	}
	for _, v := range []string{"ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"} {
		if root := os.Getenv(v); root != "" && strings.HasPrefix(p, strings.ToLower(strings.TrimRight(root, `\`))+`\`) {
			return true
		}
	}
	return false
}

// InstalledPackagePath reports whether path is inside the system's MSIX
// install root (%ProgramFiles%\WindowsApps), which only TrustedInstaller can
// write and whose files Windows verified at install. Any other folder that
// happens to be called WindowsApps — including the user-writable
// %LOCALAPPDATA%\Microsoft\WindowsApps — earns no trust.
func InstalledPackagePath(path string) bool {
	p, ok := canonicalPath(path) // review finding: "WindowsApps\..\..\Users\..." passed a text-prefix check
	if !ok {
		return false
	}
	for _, v := range []string{"ProgramW6432", "ProgramFiles"} {
		if root := os.Getenv(v); root != "" && strings.HasPrefix(p, strings.ToLower(strings.TrimRight(root, `\`))+`\windowsapps\`) {
			return true
		}
	}
	return false
}

// ResolveBare turns a bare program name ("sc.exe") into the file Windows would
// run from the system directories; other paths are returned unchanged.
func ResolveBare(p string) string {
	if p == "" || strings.ContainsAny(p, `\/`) {
		return p
	}
	root := os.Getenv("SystemRoot")
	for _, dir := range []string{root + `\System32`, root, root + `\System32\WindowsPowerShell\v1.0`} {
		cand := dir + `\` + p
		if !strings.Contains(strings.ToLower(p), ".") {
			cand += ".exe"
		}
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return p
}

// ExecutablePath extracts the program a command line runs: quoted paths, NT
// prefixes (\??\, \SystemRoot\), environment variables and unquoted paths with
// spaces. It returns "" when no executable-looking token is found.
func ExecutablePath(cmd string) string {
	c := strings.TrimSpace(ExpandEnv(cmd))
	c = strings.TrimPrefix(c, `\??\`)
	if root := os.Getenv("SystemRoot"); root != "" {
		lower := strings.ToLower(c)
		switch {
		case strings.HasPrefix(lower, `\systemroot\`):
			c = root + c[len(`\systemroot`):]
		case strings.HasPrefix(lower, `system32\`):
			c = root + `\` + c
		}
	}
	if strings.HasPrefix(c, `"`) {
		if end := strings.Index(c[1:], `"`); end >= 0 {
			return c[1 : 1+end]
		}
		return strings.Trim(c, `"`)
	}
	// Unquoted: grow the candidate one space-separated word at a time, the way
	// CreateProcess resolves "C:\Program Files\x.exe" — that ambiguity is itself
	// a classic hijack, so the first executable-looking prefix is what Windows runs.
	words := strings.Split(c, " ")
	for i := range words {
		// A word starting with / or - is a switch, never part of a path:
		// "regsvr32 /s C:\x\evil.dll" must resolve to regsvr32, not the whole line.
		if i > 0 && (strings.HasPrefix(words[i], "/") || strings.HasPrefix(words[i], "-")) {
			break
		}
		cand := strings.Join(words[:i+1], " ")
		if executable.MatchString(strings.TrimRight(cand, ",")) {
			return strings.TrimRight(cand, ",")
		}
	}
	// No extension anywhere: Windows appends .exe to the first word
	// ("svchost -k x", "powershell -c ...").
	if first := strings.Trim(words[0], `"`); first != "" && !strings.Contains(first[max(0, strings.LastIndexAny(first, `\/`)):], ".") {
		return first + ".exe"
	}
	return ""
}
