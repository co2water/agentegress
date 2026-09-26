//go:build windows

package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyFileCatalogSigned(t *testing.T) {
	// cmd.exe has no embedded signature; it is signed through a system catalog.
	s := VerifyFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	if s.Status != SigSigned || !s.Catalog {
		t.Fatalf("cmd.exe = %+v, want catalog-signed", s)
	}
	if s.Signer == "" {
		t.Errorf("cmd.exe signer empty")
	}
}

func TestVerifyFileUnsigned(t *testing.T) {
	// A freshly written file cannot carry a signature.
	p := filepath.Join(t.TempDir(), "x.exe")
	if err := os.WriteFile(p, []byte("MZ not really a program"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s := VerifyFile(p); s.Status != SigUnsigned {
		t.Fatalf("temp file = %+v, want unsigned", s)
	}
}

// Review finding: any folder named WindowsApps used to confer package trust.
func TestFakeWindowsAppsIsUnsigned(t *testing.T) {
	for _, dir := range []string{
		filepath.Join(t.TempDir(), "WindowsApps"),
		filepath.Join(t.TempDir(), "Microsoft", "WindowsApps"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "evil.exe")
		if err := os.WriteFile(p, []byte("MZ fake"), 0o644); err != nil {
			t.Fatal(err)
		}
		if s := VerifyFile(p); s.Status != SigUnsigned {
			t.Errorf("%s = %+v, want unsigned", p, s)
		}
	}
	if !InstalledPackagePath(os.Getenv("ProgramFiles") + `\WindowsApps\Claude_1\app\claude.exe`) {
		t.Error("real MSIX root not recognised")
	}
	if InstalledPackagePath(os.Getenv("LOCALAPPDATA") + `\Microsoft\WindowsApps\x.exe`) {
		t.Error("user WindowsApps trusted")
	}
}

func TestVerifyFileNeverOpensRemote(t *testing.T) {
	// 203.0.113.0/24 is a documentation range: if this were opened, the test
	// would hang on an SMB connect instead of returning at once.
	if s := VerifyFile(`\\203.0.113.9\share\x.exe`); s.Status != SigRemote {
		t.Fatalf("remote path = %+v", s)
	}
}

func TestProcessesSeesSelf(t *testing.T) {
	procs, err := Processes()
	if err != nil {
		t.Fatal(err)
	}
	me := procs[uint32(os.Getpid())]
	if me == nil || me.Path == "" || me.Cmdline == "" || me.Created.IsZero() {
		t.Fatalf("self = %+v", me)
	}
}

func TestTCPAndDNSDoNotFail(t *testing.T) {
	if _, err := TCPConnections(); err != nil {
		t.Fatal(err)
	}
	if _, err := DNSNames(); err != nil {
		t.Fatal(err)
	}
}

func TestHostCollectorsLive(t *testing.T) {
	items, notes := Autostarts()
	kinds := map[string]int{}
	noTarget := 0
	for _, a := range items {
		kinds[a.Kind]++
		if a.Target == "" {
			noTarget++
		}
	}
	t.Logf("autostarts %v, without target %d, notes %v", kinds, noTarget, notes)
	if kinds["service"] == 0 || kinds["scheduled-task"] == 0 {
		t.Errorf("expected services and scheduled tasks, got %v (notes %v)", kinds, notes)
	}
	t.Logf("host %+v", HostSettings())
	l := RecentLogons(24)
	t.Logf("logons checked=%v reason=%q failed=%d rdp=%d", l.Checked, l.Reason, len(l.Failed), len(l.RemoteDesk))
	if !l.Checked && l.Reason == "" {
		t.Error("unchecked logons must say why")
	}
}
