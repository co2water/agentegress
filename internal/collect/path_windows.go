//go:build windows

package collect

import (
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	procGetLongPathNameW = modkernel32.NewProc("GetLongPathNameW")
	procGetDriveTypeW    = modkernel32.NewProc("GetDriveTypeW")
)

const driveRemote = 4

var (
	driveMu    sync.Mutex
	driveTypes = map[byte]uintptr{}
)

// IsRemotePath reports whether path must not be opened because doing so could
// touch the network. It is an allowlist: only an absolute path on a local
// drive letter ("C:\...", optionally with a \\?\ or \??\ prefix) is safe.
// Everything else counts as remote: UNC paths in any spelling (\\server,
// \\?\UNC\, \??\UNC\, \\?\GLOBALROOT\Device\Mup\, WebDAV), other device
// paths, relative paths (resolved against a current directory that may be a
// share) and drive letters mapped to network shares. Reading a file there
// makes Windows connect, and possibly authenticate, to the server.
func IsRemotePath(path string) bool {
	d, ok := localDrive(path)
	if !ok {
		return true
	}
	driveMu.Lock()
	defer driveMu.Unlock()
	t, seen := driveTypes[d]
	if !seen {
		root, _ := syscall.UTF16PtrFromString(string([]byte{d, ':', '\\'}))
		t, _, _ = procGetDriveTypeW.Call(uintptr(unsafe.Pointer(root)))
		if t > driveNoRoot { // a letter not mapped yet may be mapped later (long-running MCP mode)
			driveTypes[d] = t
		}
	}
	return t == driveRemote
}

const driveNoRoot = 1 // DRIVE_NO_ROOT_DIR; 0 is DRIVE_UNKNOWN

// networkSpelling reports whether a path IsRemotePath refuses names another
// machine (UNC or device spellings, or a mapped network drive), as opposed to
// a bare or relative name whose file is simply unknown.
func networkSpelling(path string) bool {
	p := strings.TrimSpace(path)
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`) || strings.HasPrefix(p, `\??\`) {
		return true
	}
	_, ok := localDrive(p)
	return ok
}

// localDrive returns the lower-case drive letter of an absolute drive path.
func localDrive(path string) (byte, bool) {
	p := strings.TrimSpace(path)
	for _, prefix := range []string{`\\?\`, `\??\`} {
		if strings.HasPrefix(p, prefix) {
			p = p[len(prefix):]
			break
		}
	}
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return 0, false
	}
	d := p[0] | 0x20
	if d < 'a' || d > 'z' {
		return 0, false
	}
	return d, true
}

const fileAttributeReparsePoint = 0x400

var procGetFileAttributesW = modkernel32.NewProc("GetFileAttributesW")

// isReparsePoint reports whether the file itself is a symlink, junction or
// other reparse point. Such files are not opened: the target could be a
// network path. (A reparse point in a parent folder is still traversed.)
func isReparsePoint(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	a, _, _ := procGetFileAttributesW.Call(uintptr(unsafe.Pointer(p)))
	if a == 0xFFFFFFFF { // INVALID_FILE_ATTRIBUTES: missing; opening will fail locally
		return false
	}
	return a&fileAttributeReparsePoint != 0
}

// canonicalPath returns the lower-case form Windows would resolve path to:
// cleaned (".", "..", doubled separators), trailing dots and spaces removed
// from each component, and 8.3 short names expanded. ok is false when the
// path cannot be made canonical (remote, or a short name that does not
// expand), in which case callers must not grant it any trust.
func canonicalPath(path string) (string, bool) {
	p := strings.TrimSpace(path)
	if p == "" || IsRemotePath(p) {
		return "", false
	}
	p = strings.TrimPrefix(strings.TrimPrefix(p, `\\?\`), `\??\`)
	// "X:\dir\file:stream" is an alternate data stream: it can hang off a
	// user-writable folder while its text still matches a protected prefix.
	if strings.Contains(p[2:], ":") {
		return "", false
	}
	p = filepath.Clean(strings.ReplaceAll(p, "/", `\`))
	parts := strings.Split(p, `\`)
	for i := 1; i < len(parts); i++ {
		parts[i] = strings.TrimRight(parts[i], ". ")
	}
	p = strings.Join(parts, `\`)
	if strings.Contains(p, "~") {
		long, ok := longPathName(p)
		if !ok {
			return "", false
		}
		p = long
	}
	return strings.ToLower(p), true
}

func longPathName(p string) (string, bool) {
	in, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return "", false
	}
	buf := make([]uint16, 1024)
	n, _, _ := procGetLongPathNameW.Call(uintptr(unsafe.Pointer(in)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || int(n) > len(buf) {
		return "", false
	}
	return syscall.UTF16ToString(buf[:n]), true
}
