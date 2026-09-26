//go:build windows

package collect

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

var (
	modadvapi32       = syscall.NewLazyDLL("advapi32.dll")
	procRegEnumValueW = modadvapi32.NewProc("RegEnumValueW")
)

const (
	keyWow6464Key  = 0x100
	errNoMoreItems = 259
	errMoreData    = 234
	regSZ          = 1
	regExpandSZ    = 2
	regDWORD       = 4
)

type regKey syscall.Handle

func regOpen(root syscall.Handle, path string) (regKey, bool) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	var h syscall.Handle
	if syscall.RegOpenKeyEx(root, p, 0, syscall.KEY_READ|keyWow6464Key, &h) != nil {
		return 0, false
	}
	return regKey(h), true
}

func (k regKey) close() { syscall.RegCloseKey(syscall.Handle(k)) }

func (k regKey) subkeys() []string {
	var out []string
	buf := make([]uint16, 512)
	for i := uint32(0); ; i++ {
		n := uint32(len(buf))
		if syscall.RegEnumKeyEx(syscall.Handle(k), i, &buf[0], &n, nil, nil, nil, nil) != nil {
			return out
		}
		out = append(out, syscall.UTF16ToString(buf[:n]))
	}
}

// regValue is a string or DWORD registry value.
type regValue struct {
	Name  string
	Str   string
	DWord uint32
	Type  uint32
}

func (k regKey) values() []regValue {
	var out []regValue
	name := make([]uint16, 16384)
	data := make([]byte, 4096)
	for i := uint32(0); ; i++ {
		nameLen := uint32(len(name))
		dataLen := uint32(len(data))
		var typ uint32
		r, _, _ := procRegEnumValueW.Call(uintptr(k), uintptr(i), uintptr(unsafe.Pointer(&name[0])),
			uintptr(unsafe.Pointer(&nameLen)), 0, uintptr(unsafe.Pointer(&typ)),
			uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&dataLen)))
		if r == errMoreData {
			data = make([]byte, dataLen+2)
			i-- // retry the same index with a bigger buffer
			continue
		}
		if r != 0 { // errNoMoreItems or a real error: stop either way
			return out
		}
		out = append(out, decodeRegValue(syscall.UTF16ToString(name[:nameLen]), typ, data[:dataLen]))
	}
}

func (k regKey) value(name string) (regValue, bool) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return regValue{}, false
	}
	var typ, n uint32
	if syscall.RegQueryValueEx(syscall.Handle(k), p, nil, &typ, nil, &n) != nil || n == 0 {
		return regValue{}, false
	}
	data := make([]byte, n)
	if syscall.RegQueryValueEx(syscall.Handle(k), p, nil, &typ, &data[0], &n) != nil {
		return regValue{}, false
	}
	return decodeRegValue(name, typ, data[:n]), true
}

func decodeRegValue(name string, typ uint32, data []byte) regValue {
	v := regValue{Name: name, Type: typ}
	switch typ {
	case regSZ, regExpandSZ:
		u := make([]uint16, len(data)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(data[2*i:])
		}
		v.Str = syscall.UTF16ToString(u)
	case regDWORD:
		if len(data) >= 4 {
			v.DWord = binary.LittleEndian.Uint32(data)
		}
	}
	return v
}
