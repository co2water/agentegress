//go:build windows

package collect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

// Autostarts enumerates Run keys, Winlogon, startup folders, services and the
// scheduled tasks visible to the current user. Errors in one source are
// returned as notes; the others still run.
func Autostarts() ([]Autostart, []string) {
	var out, items []Autostart
	var notes []string
	out = append(out, runKeys()...)
	out = append(out, winlogon()...)
	out = append(out, startupFolders()...)
	out = append(out, services()...)
	items, err := scheduledTasks()
	if err != nil {
		notes = append(notes, "scheduled tasks: "+err.Error())
	}
	out = append(out, items...)
	return out, notes
}

func runKeys() []Autostart {
	type loc struct {
		root  syscall.Handle
		scope string
		path  string
	}
	var locs []loc
	for _, r := range []struct {
		root  syscall.Handle
		scope string
		label string
	}{{syscall.HKEY_CURRENT_USER, "user", "HKCU"}, {syscall.HKEY_LOCAL_MACHINE, "machine", "HKLM"}} {
		for _, p := range []string{
			`Software\Microsoft\Windows\CurrentVersion\Run`,
			`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
			`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
			`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
			`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		} {
			locs = append(locs, loc{r.root, r.scope, r.label + `\` + p})
		}
	}
	var out []Autostart
	for _, l := range locs {
		k, ok := regOpen(l.root, l.path[5:])
		if !ok {
			continue
		}
		for _, v := range k.values() {
			if v.Str == "" {
				continue
			}
			out = append(out, Autostart{Kind: "run-key", Scope: l.scope, Location: l.path, Name: v.Name,
				Command: v.Str}.Resolve())
		}
		k.close()
	}
	return out
}

// winlogon reports Shell and Userinit only when they differ from the Windows
// defaults; appending a program to either is a classic persistence trick.
func winlogon() []Autostart {
	const path = `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
	k, ok := regOpen(syscall.HKEY_LOCAL_MACHINE, path)
	if !ok {
		return nil
	}
	defer k.close()
	var out []Autostart
	defaults := map[string][]string{
		"Shell":    {"explorer.exe"},
		"Userinit": {`c:\windows\system32\userinit.exe,`, `c:\windows\system32\userinit.exe`},
	}
	for name, want := range defaults {
		v, ok := k.value(name)
		if !ok {
			continue
		}
		cur := strings.ToLower(strings.TrimSpace(v.Str))
		isDefault := false
		for _, w := range want {
			if cur == w {
				isDefault = true
			}
		}
		if !isDefault {
			out = append(out, Autostart{Kind: "winlogon", Scope: "machine", Location: `HKLM\` + path, Name: name,
				Command: v.Str}.Resolve())
		}
	}
	return out
}

func startupFolders() []Autostart {
	var out []Autostart
	dirs := []struct{ scope, dir string }{
		{"user", filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)},
		{"machine", filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`)},
	}
	for _, d := range dirs {
		entries, err := os.ReadDir(d.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			p := filepath.Join(d.dir, e.Name())
			a := Autostart{Kind: "startup-folder", Scope: d.scope, Location: d.dir, Name: e.Name(), Command: p, Target: p}
			if strings.EqualFold(filepath.Ext(p), ".lnk") {
				if b, err := os.ReadFile(p); err == nil {
					if s, err := ParseShortcut(b); err == nil {
						a.Target = s.Target
						a.Command = strings.TrimSpace(s.Target + " " + s.Arguments)
						if pl := Payload(a.Command, s.Target); pl != "" {
							a.Target, a.Host = pl, s.Target
						}
					}
				}
			}
			out = append(out, a)
		}
	}
	return out
}

func services() []Autostart {
	const root = `SYSTEM\CurrentControlSet\Services`
	k, ok := regOpen(syscall.HKEY_LOCAL_MACHINE, root)
	if !ok {
		return nil
	}
	defer k.close()
	var out []Autostart
	for _, name := range k.subkeys() {
		sk, ok := regOpen(syscall.HKEY_LOCAL_MACHINE, root+`\`+name)
		if !ok {
			continue
		}
		typ, _ := sk.value("Type")
		start, _ := sk.value("Start")
		img, _ := sk.value("ImagePath")
		sk.close()
		// Only user-mode services (own or shared process); skip drivers.
		if typ.DWord&0x30 == 0 || img.Str == "" {
			continue
		}
		a := Autostart{Kind: "service", Scope: "machine", Location: `HKLM\` + root + `\` + name, Name: name,
			Command: img.Str, Disabled: start.DWord == 4}
		a = a.Resolve()
		// Shared svchost services run a DLL named under Parameters\ServiceDll.
		if strings.Contains(strings.ToLower(img.Str), `svchost`) {
			if pk, ok := regOpen(syscall.HKEY_LOCAL_MACHINE, root+`\`+name+`\Parameters`); ok {
				if dll, ok := pk.value("ServiceDll"); ok && dll.Str != "" {
					a.Target = ExpandEnv(dll.Str)
				}
				pk.close()
			}
		}
		out = append(out, a)
	}
	return out
}

func scheduledTasks() ([]Autostart, error) {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "/query", "/xml", "ONE")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(b) {
		b = oemToUTF8(b)
	}
	return ParseTasksXML(b)
}

var procMultiByteToWideChar = modkernel32.NewProc("MultiByteToWideChar")

// oemToUTF8 converts console output in the OEM code page (e.g. CP950 on
// Traditional Chinese Windows) to UTF-8.
func oemToUTF8(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	const cpOEM = 1
	n, _, _ := procMultiByteToWideChar.Call(cpOEM, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if n == 0 {
		return b
	}
	u := make([]uint16, n)
	procMultiByteToWideChar.Call(cpOEM, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&u[0])), n)
	return []byte(syscall.UTF16ToString(u))
}

// HostSettings reads Remote Desktop and firewall profile state.
func HostSettings() HostConfig {
	var h HostConfig
	if k, ok := regOpen(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`); ok {
		if v, ok := k.value("fDenyTSConnections"); ok {
			h.RDPKnown, h.RDPEnabled = true, v.DWord == 0
		}
		k.close()
	}
	for _, p := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
		k, ok := regOpen(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`+p)
		if !ok {
			continue
		}
		if v, ok := k.value("EnableFirewall"); ok {
			h.FirewallKnown = true
			if v.DWord == 0 {
				h.FirewallDisabled = append(h.FirewallDisabled, strings.TrimSuffix(p, "Profile"))
			}
		}
		k.close()
	}
	return h
}
