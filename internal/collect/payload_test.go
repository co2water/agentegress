package collect

import (
	"os"
	"testing"
)

// Second code review (2026-09-25): bypasses of payload extraction (first file
// wins, extension allow-list, interpreters) and false alarms from reading
// ordinary arguments as payloads. Test data only; keep it off command lines.
func TestPayloadSecondReview(t *testing.T) {
	sys := os.Getenv("SystemRoot") + `\System32\`
	cases := []struct{ cmd, host, want string }{
		// bypasses
		{`rundll32.exe shell32.dll,Control_RunDLL C:\Users\x\evil.cpl`, sys + "rundll32.exe", `C:\Users\x\evil.cpl`},
		{`rundll32.exe url.dll,FileProtocolHandler C:\Users\x\evil.exe`, sys + "rundll32.exe", `C:\Users\x\evil.exe`},
		{`rundll32.exe C:\Users\x\a.tmp,DllMain`, sys + "rundll32.exe", `C:\Users\x\a.tmp`},
		{`rundll32.exe C:\Users\x\evil,Entry`, sys + "rundll32.exe", `C:\Users\x\evil`},
		{`regsvr32 /s C:\Users\x\a.txt`, sys + "regsvr32.exe", `C:\Users\x\a.txt`},
		{`wscript //E:jscript C:\Users\x\a.txt`, sys + "wscript.exe", `C:\Users\x\a.txt`},
		{`mshta C:\Users\x\a.txt`, sys + "mshta.exe", `C:\Users\x\a.txt`},
		{`cmd /c C:\Windows\System32\wscript.exe C:\Users\x\evil.js`, sys + "cmd.exe", `C:\Users\x\evil.js`},
		{`cmd /c start "" /min C:\Users\x\a.exe`, sys + "cmd.exe", `C:\Users\x\a.exe`},
		{`"C:\Program Files\nodejs\node.exe" C:\Users\x\evil.js`, `C:\Program Files\nodejs\node.exe`, `C:\Users\x\evil.js`},
		{`pythonw.exe --no-warn C:\Users\x\tool.pyw`, `C:\Python\pythonw.exe`, `C:\Users\x\tool.pyw`},
		{`javaw -jar C:\Users\x\a.jar`, `C:\Java\bin\javaw.exe`, `C:\Users\x\a.jar`},
		{`powershell -NoProfile -f C:\Users\x\s.ps1`, sys + `WindowsPowerShell\v1.0\powershell.exe`, `C:\Users\x\s.ps1`},
		// no payload: inline code, built-ins, arguments that are data
		{`powershell -Command "Remove-Item C:\Users\x\AppData\Local\Temp\build\out.exe"`, sys + `WindowsPowerShell\v1.0\powershell.exe`, ""},
		{`powershell -Command "& 'C:\x\a.ps1'"`, sys + `WindowsPowerShell\v1.0\powershell.exe`, `C:\x\a.ps1`}, // third review, item 4
		{`cmd /c dir C:\Users\x\Downloads\setup.exe`, sys + "cmd.exe", ""},
		{`cmd /c echo done > C:\Users\x\log.txt`, sys + "cmd.exe", ""},
		{`python -c "print(1)" C:\Users\x\data.csv`, `C:\Python\python.exe`, ""},
		{`node -e "1" C:\Users\x\evil.js`, `C:\node\node.exe`, ""},
		{`python -m http.server`, `C:\Python\python.exe`, ""},
		{`rundll32.exe shell32.dll,Control_RunDLL`, sys + "rundll32.exe", ""}, // only a protected system DLL
		{`C:\Program Files\App\app.exe C:\Users\x\z.dll`, `C:\Program Files\App\app.exe`, ""},
	}
	for _, c := range cases {
		if got := Payload(c.cmd, c.host); got != c.want {
			t.Errorf("Payload(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

// Second review, defect D: spellings that resolve into writable folders.
func TestProtectedSystemPathCanonical(t *testing.T) {
	root := os.Getenv("SystemRoot")
	for _, p := range []string{
		root + `\System32\.\spool\drivers\color\x.exe`,
		root + `\System32\\spool\drivers\color\x.exe`,
		root + `\System32\spool.\drivers\color\x.exe`,
		root + `\System32\spool \drivers\color\x.exe`,
		root + `\System32\TASKS_~1\x.exe`,
		`\\server\share\Windows\System32\x.exe`,
	} {
		if ProtectedSystemPath(p) {
			t.Errorf("%q treated as protected", p)
		}
	}
	if !ProtectedSystemPath(root + `\System32\.\svchost.exe`) {
		t.Error("clean system path no longer protected")
	}
	pf := os.Getenv("ProgramFiles")
	if InstalledPackagePath(pf + `\WindowsApps\..\..\Users\x\evil.exe`) {
		t.Error("WindowsApps\\..\\.. escape trusted")
	}
}

// Second review, defect E: network paths must never be opened.
func TestRemotePaths(t *testing.T) {
	for _, p := range []string{`\\203.0.113.9\share\x.bat`, `\\?\UNC\server\share\x.dll`, `\\host@SSL\DavWWWRoot\x.exe`, `//server/share/x`,
		// Third review, item 1: NT-namespace spellings of a share, device
		// paths and relative paths (resolved against an unknown directory).
		`\??\UNC\server\share\x.dll`, `\\?\GLOBALROOT\Device\Mup\server\share\x.dll`, `\\.\GLOBALROOT\Device\Mup\s\x.dll`,
		`\Device\Mup\server\share\x.dll`, `\\?\Volume{00000000-0000-0000-0000-000000000000}\x.exe`,
		`x.exe`, `.\tools\x.exe`, `C:x.exe`, `\x.exe`, ``} {
		if !IsRemotePath(p) {
			t.Errorf("%q not treated as remote", p)
		}
	}
	for _, p := range []string{os.Getenv("SystemRoot") + `\System32\cmd.exe`, `\\?\C:\Windows\x.exe`, `\??\C:\Windows\x.exe`} {
		if IsRemotePath(p) {
			t.Errorf("%q treated as remote", p)
		}
	}
}
