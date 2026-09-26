//go:build windows

package collect

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
	modntdll                       = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationProcess  = modntdll.NewProc("NtQueryInformationProcess")
)

const (
	processQueryLimitedInformation = 0x1000
	processCommandLineInformation  = 60 // Windows 8.1+

	statusInfoLengthMismatch = 0xC0000004
	statusBufferOverflow     = 0x80000005
	statusBufferTooSmall     = 0xC0000023
)

// Processes snapshots all processes and enriches each with image path and command
// line where the current token is allowed to read them.
func Processes() (map[uint32]*Process, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer syscall.CloseHandle(snap)

	procs := map[uint32]*Process{}
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = syscall.Process32First(snap, &pe); err == nil; err = syscall.Process32Next(snap, &pe) {
		procs[pe.ProcessID] = &Process{
			PID:  pe.ProcessID,
			PPID: pe.ParentProcessID,
			Name: syscall.UTF16ToString(pe.ExeFile[:]),
		}
	}
	if !errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("Process32Next: %w", err)
	}
	for _, p := range procs {
		enrich(p)
	}
	return procs, nil
}

var errPseudo = errors.New("system pseudo-process")

func enrich(p *Process) {
	if p.PID == 0 || p.PID == 4 {
		p.PathErr, p.CmdErr = errPseudo, errPseudo
		return
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, p.PID)
	if err != nil {
		p.PathErr, p.CmdErr = err, err
		return
	}
	defer syscall.CloseHandle(h)
	p.Path, p.PathErr = imagePath(h)
	var created, exited, kernel, user syscall.Filetime
	if syscall.GetProcessTimes(h, &created, &exited, &kernel, &user) == nil {
		p.Created = time.Unix(0, created.Nanoseconds())
	}
	p.Cmdline, p.CmdErr = commandLine(h)
}

func imagePath(h syscall.Handle) (string, error) {
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	r, _, e := procQueryFullProcessImageNameW.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return "", e
	}
	return syscall.UTF16ToString(buf[:n]), nil
}

// commandLine reads ProcessCommandLineInformation, which needs only
// PROCESS_QUERY_LIMITED_INFORMATION (no PEB read, no debug privilege).
func commandLine(h syscall.Handle) (string, error) {
	size := uint32(2048)
	for range 5 {
		buf := make([]byte, size)
		var ret uint32
		r, _, _ := procNtQueryInformationProcess.Call(uintptr(h), processCommandLineInformation,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&ret)))
		switch uint32(r) {
		case 0:
			return decodeUnicodeString(buf)
		case statusInfoLengthMismatch, statusBufferOverflow, statusBufferTooSmall:
			size = max(ret, size*2)
			continue
		default:
			return "", fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%08X", uint32(r))
		}
	}
	return "", errors.New("NtQueryInformationProcess: buffer kept growing")
}

// decodeUnicodeString reads a UNICODE_STRING header (amd64 layout) whose Buffer
// points back into buf, without converting the raw pointer into a Go pointer.
func decodeUnicodeString(buf []byte) (string, error) {
	le := binary.LittleEndian
	length := int(le.Uint16(buf[0:]))
	if length == 0 {
		return "", nil
	}
	ptr := uintptr(le.Uint64(buf[8:]))
	off := int(ptr - uintptr(unsafe.Pointer(&buf[0])))
	if off < 16 || off+length > len(buf) {
		return "", errors.New("command line buffer outside result")
	}
	u := make([]uint16, length/2)
	for i := range u {
		u[i] = le.Uint16(buf[off+2*i:])
	}
	return syscall.UTF16ToString(u), nil
}
