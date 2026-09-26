//go:build windows

package collect

import (
	"syscall"
	"unsafe"
)

const tokenElevation = 20

// Elevated reports whether the current process token is elevated (admin).
func Elevated() bool {
	p, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var t syscall.Token
	if syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &t) != nil {
		return false
	}
	defer t.Close()
	var elevated, n uint32
	if syscall.GetTokenInformation(t, tokenElevation, (*byte)(unsafe.Pointer(&elevated)), 4, &n) != nil {
		return false
	}
	return elevated != 0
}
