//go:build windows

package collect

import (
	"os"
	"testing"
)

// Test data only: these paths are known application-control bypass folders.
// Keep them out of shell command lines (Defender flags the text).
func TestProtectedSystemPath(t *testing.T) {
	root := os.Getenv("SystemRoot")
	cases := map[string]bool{
		root + `\System32\svchost.exe`:                         true,
		root + `\SysWOW64\cmd.exe`:                             true,
		root + `\System32\spool\drivers\color\x.exe`:           false,
		root + `\System32\Tasks\x.exe`:                         false,
		root + `\System32\..\Temp\x.exe`:                       false,
		root + `\Temp\x.exe`:                                   false,
		`C:\Program Files\App\app.exe`:                         false,
		`C:\Users\x\AppData\Local\Microsoft\WindowsApps\a.exe`: false,
		// Third review, item 2: an alternate data stream on a writable folder.
		root + `\System32\Tasks:x.dll`:    false,
		root + `\System32:x.dll`:          false,
		`\??\` + root + `\System32\a.exe`: true,
	}
	for p, want := range cases {
		if got := ProtectedSystemPath(p); got != want {
			t.Errorf("ProtectedSystemPath(%q) = %v, want %v", p, got, want)
		}
	}
}
