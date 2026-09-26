//go:build windows

package collect

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"unsafe"
)

var (
	moddnsapi                = syscall.NewLazyDLL("dnsapi.dll")
	procDnsGetCacheDataTable = moddnsapi.NewProc("DnsGetCacheDataTable")
	procDnsQuery             = moddnsapi.NewProc("DnsQuery_W")
	procDnsFree              = moddnsapi.NewProc("DnsFree")
)

const (
	dnsTypeA            = 1
	dnsTypeAAAA         = 28
	dnsQueryNoWireQuery = 0x10 // answer from the local cache only, never send a packet
	dnsFreeFlat         = 0
	dnsFreeRecordList   = 1
)

// DNS_CACHE_ENTRY (undocumented, stable since Windows 7).
type dnsCacheEntry struct {
	next    *dnsCacheEntry
	name    *uint16
	typ     uint16
	dataLen uint16
	flags   uint32
}

// DNS_RECORDW, amd64 layout; data is the union.
type dnsRecord struct {
	next     *dnsRecord
	name     *uint16
	typ      uint16
	length   uint16
	flags    uint32
	ttl      uint32
	reserved uint32
	data     [40]byte
}

// DNSNames maps addresses to the host names that resolved to them, using only the
// local resolver cache. Entries expire with their TTL, so long-lived connections
// may have no name; that is reported as missing rather than guessed.
func DNSNames() (map[netip.Addr][]string, error) {
	var head *dnsCacheEntry
	r, _, e := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if r == 0 {
		return nil, fmt.Errorf("DnsGetCacheDataTable: %v", e)
	}
	names := map[string]bool{}
	for ent := head; ent != nil; {
		if ent.name != nil {
			names[strings.ToLower(utf16PtrToString(ent.name))] = true
		}
		next := ent.next
		procDnsFree.Call(uintptr(unsafe.Pointer(ent.name)), dnsFreeFlat)
		procDnsFree.Call(uintptr(unsafe.Pointer(ent)), dnsFreeFlat)
		ent = next
	}

	out := map[netip.Addr][]string{}
	for name := range names {
		if name == "" {
			continue
		}
		cachedAddrs(name, dnsTypeA, out)
		cachedAddrs(name, dnsTypeAAAA, out)
	}
	for a := range out {
		slices.Sort(out[a])
		out[a] = slices.Compact(out[a])
	}
	return out, nil
}

func cachedAddrs(name string, typ uint16, out map[netip.Addr][]string) {
	n16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	var rec *dnsRecord
	r, _, _ := procDnsQuery.Call(uintptr(unsafe.Pointer(n16)), uintptr(typ), dnsQueryNoWireQuery,
		0, uintptr(unsafe.Pointer(&rec)), 0)
	if r != 0 || rec == nil {
		return
	}
	defer procDnsFree.Call(uintptr(unsafe.Pointer(rec)), dnsFreeRecordList)
	for x := rec; x != nil; x = x.next {
		var a netip.Addr
		switch {
		case x.typ == dnsTypeA && typ == dnsTypeA:
			a = netip.AddrFrom4([4]byte(x.data[:4]))
		case x.typ == dnsTypeAAAA && typ == dnsTypeAAAA:
			a = netip.AddrFrom16([16]byte(x.data[:16])).Unmap()
		}
		if a.IsValid() {
			out[a] = append(out[a], name)
		}
	}
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var s []uint16
	for i := range 4096 {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(p), 2*i))
		if c == 0 {
			break
		}
		s = append(s, c)
	}
	return syscall.UTF16ToString(s)
}
