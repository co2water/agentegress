//go:build windows

package collect

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Winget review (2026-11-04): a missing file and an unreadable one used to
// share one detail, so a dangling autostart rated like a locked binary.
func TestVerifyFileMissingIsDistinct(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{
		filepath.Join(dir, "gone.exe"),
		filepath.Join(dir, "no-such-folder", "gone.exe"),
	} {
		if s := VerifyFile(p); s.Status != SigError || s.Detail != DetailMissing {
			t.Errorf("%s = %+v, want missing", p, s)
		}
	}

	// Present but held open without sharing: unreadable, not missing.
	p := filepath.Join(dir, "locked.exe")
	if err := os.WriteFile(p, []byte("MZ not really a program"), 0o644); err != nil {
		t.Fatal(err)
	}
	p16, _ := syscall.UTF16PtrFromString(p)
	h, err := syscall.CreateFile(p16, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(h)
	if s := VerifyFile(p); s.Status != SigError || s.Detail == DetailMissing {
		t.Errorf("locked file = %+v, want an error that is not missing", s)
	}
}
