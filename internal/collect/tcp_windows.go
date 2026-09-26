//go:build windows

package collect

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

var (
	modiphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afInet                = 2
	afInet6               = 23
	tcpTableOwnerPIDAll   = 5
	errInsufficientBuffer = 122
)

// TCPConnections returns every IPv4 and IPv6 TCP endpoint with its owning PID.
func TCPConnections() ([]TCPConn, error) {
	v4, err := tcpTable(afInet)
	if err != nil {
		return nil, err
	}
	v6, err := tcpTable(afInet6)
	if err != nil {
		return nil, err
	}
	return append(v4, v6...), nil
}

func tcpTable(af uint32) ([]TCPConn, error) {
	var buf []byte
	var size uint32
	ok := false
	// The table can grow between the sizing call and the real call, so retry a few times.
	for range 5 {
		var p unsafe.Pointer
		if len(buf) > 0 {
			p = unsafe.Pointer(&buf[0])
		}
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(p), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(af), tcpTableOwnerPIDAll, 0)
		if r == 0 {
			ok = true
			break
		}
		if r != errInsufficientBuffer {
			return nil, fmt.Errorf("GetExtendedTcpTable(af=%d): error %d", af, r)
		}
		buf = make([]byte, size+4096)
		size = uint32(len(buf))
	}
	if !ok {
		return nil, fmt.Errorf("GetExtendedTcpTable(af=%d): table kept growing", af)
	}
	if len(buf) < 4 {
		return nil, nil
	}

	n := int(binary.LittleEndian.Uint32(buf[0:4]))
	le := binary.LittleEndian
	var out []TCPConn
	switch af {
	case afInet: // MIB_TCPROW_OWNER_PID, 24 bytes
		for i := range n {
			r := buf[4+i*24 : 4+(i+1)*24]
			out = append(out, TCPConn{
				State:  TCPState(le.Uint32(r[0:])),
				Local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), port(r[8:])),
				Remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), port(r[16:])),
				PID:    le.Uint32(r[20:]),
			})
		}
	case afInet6: // MIB_TCP6ROW_OWNER_PID, 56 bytes
		for i := range n {
			r := buf[4+i*56 : 4+(i+1)*56]
			out = append(out, TCPConn{
				Local:  netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[0:16])).Unmap(), port(r[20:])),
				Remote: netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[24:40])).Unmap(), port(r[44:])),
				State:  TCPState(le.Uint32(r[48:])),
				PID:    le.Uint32(r[52:]),
			})
		}
	}
	return out, nil
}

// port decodes a DWORD whose low two bytes hold the port in network byte order.
func port(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
