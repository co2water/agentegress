//go:build windows

package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Third code review (2026-09-26), item 4: command-line spellings that hid the
// file a host program runs. Test data only; keep it off command lines.
func TestPayloadThirdReview(t *testing.T) {
	sys := os.Getenv("SystemRoot") + `\System32\`
	ps := sys + `WindowsPowerShell\v1.0\powershell.exe`
	cases := []struct{ cmd, host, want string }{
		// cmd.exe switch spellings
		{`cmd /c"C:\Users\x\a.exe"`, sys + "cmd.exe", `C:\Users\x\a.exe`},
		{`cmd /q/c C:\Users\x\a.exe`, sys + "cmd.exe", `C:\Users\x\a.exe`},
		{`cmd /d /s /c "C:\Users\x\a.exe --flag"`, sys + "cmd.exe", `C:\Users\x\a.exe`},
		{`cmd /c ""C:\Users\x y\a.exe" --flag"`, sys + "cmd.exe", `C:\Users\x y\a.exe`},
		{`cmd /c "C:\Users\x y\a.exe" --flag`, sys + "cmd.exe", `C:\Users\x y\a.exe`},
		{`cmd /s/c"wscript C:\Users\x\a.js"`, sys + "cmd.exe", `C:\Users\x\a.js`},
		// PowerShell without -File
		{`powershell C:\Users\x\s.ps1`, ps, `C:\Users\x\s.ps1`},
		{`powershell -NoProfile -ExecutionPolicy Bypass C:\Users\x\s.ps1`, ps, `C:\Users\x\s.ps1`},
		{`powershell -ep Bypass -w hidden "C:\Users\x\s.ps1"`, ps, `C:\Users\x\s.ps1`},
		{`powershell -Command C:\Users\x\a.exe`, ps, `C:\Users\x\a.exe`},
		{`powershell -c "& 'C:\Users\x y\s.ps1' -Arg 1"`, ps, `C:\Users\x y\s.ps1`},
		{`pwsh -nop -c mshta C:\Users\x\a.hta`, `C:\Program Files\PowerShell\7\pwsh.exe`, `C:\Users\x\a.hta`},
		// conhost as a launcher
		{`conhost.exe --headless C:\Users\x\a.exe`, sys + "conhost.exe", `C:\Users\x\a.exe`},
		{`conhost --width 80 --headless cmd /c C:\Users\x\a.bat`, sys + "conhost.exe", `C:\Users\x\a.bat`},
		// Fourth review: a fully quoted program with spaces stays whole
		// (it became "C:\Program"), and two more spellings.
		{`cmd.exe /c "C:\Program Files\Vendor App\start.bat"`, sys + "cmd.exe", `C:\Program Files\Vendor App\start.bat`},
		{`cmd /c "C:\Users\bob\My Tools\agent.exe"`, sys + "cmd.exe", `C:\Users\bob\My Tools\agent.exe`},
		{`cmd /c "C:\Users\x\a.exe --flag"`, sys + "cmd.exe", `C:\Users\x\a.exe`},
		{`cmd /s /c "C:\Users\x y\a.exe"`, sys + "cmd.exe", `C:\Users\x`},
		{`cmd.exe /cC:\Users\x\a.exe`, sys + "cmd.exe", `C:\Users\x\a.exe`},
		{`conhost.exe --headless --vtmode xterm C:\Users\x\a.exe`, sys + "conhost.exe", `C:\Users\x\a.exe`},
		// still nothing to judge
		{`conhost.exe 0xffffffff -ForceV1`, sys + "conhost.exe", ""},
		{`powershell -Command -`, ps, ""},
		{`powershell -Command "Get-Process | Out-File C:\Users\x\p.txt"`, ps, ""},
		{`powershell -c "& { Write-Host 1 }"`, ps, ""},
		{`powershell -EncodedCommand AAAA`, ps, ""},
		{`powershell .\build.ps1`, ps, ""},             // relative: the working directory is unknown
		{`node dist\index.js`, `C:\node\node.exe`, ""}, // likewise
	}
	for _, c := range cases {
		if got := Payload(c.cmd, c.host); got != c.want {
			t.Errorf("Payload(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

// Item 5: only folders known to be admin-only are trusted as such.
func TestAdminOnlyPath(t *testing.T) {
	root := os.Getenv("SystemRoot")
	pf := os.Getenv("ProgramFiles")
	cases := map[string]bool{
		root + `\System32\svchost.exe`:          true,
		root + `\explorer.exe`:                  true,
		root + `\Microsoft.NET\Framework\x.dll`: true,
		pf + `\App\app.exe`:                     true,
		pf + `\App\..\..\tools\x.exe`:           false,
		root + `\Temp\x.exe`:                    false,
		root + `\Tasks\x.exe`:                   false,
		root + `\System32\Tasks\x.exe`:          false,
		root + `\tracing\x.exe`:                 false,
		`C:\tools\x.exe`:                        false,
		`D:\x.exe`:                              false,
		os.Getenv("ProgramData") + `\x\y.exe`:   false,
		os.Getenv("USERPROFILE") + `\x.exe`:     false,
		`\\server\share\x.exe`:                  false,
		root + `\explorer.exe:ads`:              false,
		`x.exe`:                                 false,
	}
	for p, want := range cases {
		if got := AdminOnlyPath(p); got != want {
			t.Errorf("AdminOnlyPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// Fifth review, finding 1: a quoted command line after /c is only kept whole
// when it names an existing file (cmd.exe's rule); otherwise the program and
// its arguments are split and the payload is found as before.
func TestCmdQuotesFifthReview(t *testing.T) {
	sys := os.Getenv("SystemRoot") + `\System32\`
	cmd := sys + "cmd.exe"
	for _, c := range []struct{ line, want string }{
		{`cmd /c "wscript C:\Users\x\a.vbs"`, `C:\Users\x\a.vbs`},
		{`cmd /c "start /min wscript C:\Users\x\a.vbs"`, `C:\Users\x\a.vbs`},
		{`cmd /c "regsvr32 /s C:\Users\x\a.dll"`, `C:\Users\x\a.dll`},
		{`cmd /c "powershell -File C:\Users\x\a.ps1"`, `C:\Users\x\a.ps1`},
		{`cmd /c "node C:\Users\x\server.js"`, `C:\Users\x\server.js`},
		{`cmd /c "C:\Windows\System32\cmd.exe /c \\server\share\tool.exe"`, `\\server\share\tool.exe`},
		{`cmd /c "C:\Users\x\a.exe C:\Users\x\b.exe"`, `C:\Users\x\a.exe`},
		{`cmd /c "C:\Program Files (x86)\Vendor\x.exe"`, `C:\Program Files (x86)\Vendor\x.exe`},
	} {
		if got := Payload(c.line, cmd); got != c.want {
			t.Errorf("Payload(%q) = %q, want %q", c.line, got, c.want)
		}
	}
	// With real files: an existing program whose path has spaces stays whole;
	// an existing program followed by arguments is split.
	dir := filepath.Join(t.TempDir(), "My Tools")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(dir, "run.bat")
	if err := os.WriteFile(prog, []byte("@echo off"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Payload(`cmd /c "`+prog+`"`, cmd); got != prog {
		t.Errorf("existing quoted program = %q, want %q", got, prog)
	}
	plain := filepath.Join(filepath.Dir(dir), "a.exe")
	if err := os.WriteFile(plain, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Payload(`cmd /c "`+plain+` --flag x"`, cmd); got != plain {
		t.Errorf("existing program with arguments = %q, want %q", got, plain)
	}
	// Sixth review: a quoted program named without its extension (found
	// through PATHEXT) stays whole; a split first word that is a script found
	// through PATHEXT is taken as the program.
	noExt := strings.TrimSuffix(prog, ".bat")
	if got := Payload(`cmd /c "`+noExt+`"`, cmd); got != noExt {
		t.Errorf("quoted program without extension = %q, want %q", got, noExt)
	}
	upd := filepath.Join(filepath.Dir(dir), "upd")
	if err := os.WriteFile(upd+".vbs", []byte("'"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Payload(`cmd /c "`+upd+` `+plain+`"`, cmd); got != upd {
		t.Errorf("script found through PATHEXT = %q, want %q", got, upd)
	}
	// A link counts as existing without being followed (os.Lstat).
	junction := filepath.Join(filepath.Dir(dir), "j")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, dir).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	if !localFile(junction) {
		t.Error("junction not seen as an existing entry")
	}
}

// Fourth review, finding 5: a bare name that did not resolve is unknown, not
// a network file (it was reported as remote and worded as "signed").
func TestVerifyBareNameIsNotRemote(t *testing.T) {
	if s := VerifyFile("vendorhelper.exe"); s.Status != SigError {
		t.Errorf("bare name = %+v, want an error status", s)
	}
	if s := VerifyFile(`\\server\share\x.exe`); s.Status != SigRemote {
		t.Errorf("UNC = %+v, want remote", s)
	}
}

// Item 1: a file that is a link is not followed (its target could be a share).
func TestReparsePointNotOpened(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.exe")
	if err := os.WriteFile(target, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s := VerifyFile(target); s.Status != SigUnsigned {
		t.Errorf("VerifyFile(real file) = %+v, want unsigned", s)
	}
	// A directory junction needs no privilege; a file symlink usually does.
	junction := filepath.Join(dir, "j")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, dir).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v %s", err, out)
	}
	if !isReparsePoint(junction) {
		t.Error("junction not seen as a reparse point")
	}
	if s := VerifyFile(junction); s.Status != SigError {
		t.Errorf("VerifyFile(junction) = %+v, want a not-followed error", s)
	}
	if isReparsePoint(target) || isReparsePoint(filepath.Join(dir, "missing.exe")) {
		t.Error("plain or missing file seen as a reparse point")
	}
	// File symlinks (fourth review, finding 7; fifth review, findings 3–4):
	// followed once to a local target, resolved the way Windows does.
	link := filepath.Join(dir, "link.exe")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("file symlinks not tested (need Developer Mode or admin): %v", err)
	}
	if s := VerifyFile(link); s.Status != SigUnsigned {
		t.Errorf("VerifyFile(link to local file) = %+v, want the target verified (unsigned)", s)
	}
	chain := filepath.Join(dir, "chain.exe")
	if err := os.Symlink(link, chain); err == nil {
		if s := VerifyFile(chain); s.Status != SigError {
			t.Errorf("VerifyFile(link to link) = %+v, want not followed", s)
		}
	}
	unc := filepath.Join(dir, "unc.exe")
	if err := os.Symlink(`\\server\share\x.exe`, unc); err == nil {
		if s := VerifyFile(unc); s.Status != SigError {
			t.Errorf("VerifyFile(link to share) = %+v, want not followed", s)
		}
	}
	// Root-relative target: resolved from the volume root, not the folder.
	rootRel := `\` + strings.TrimPrefix(target, filepath.VolumeName(target)+`\`)
	rr := filepath.Join(dir, "rootrel.exe")
	if err := os.Symlink(rootRel, rr); err == nil {
		if s := VerifyFile(rr); s.Status != SigUnsigned {
			t.Errorf("VerifyFile(root-relative link) = %+v, want the target verified", s)
		}
	}
}
