//go:build windows

package collect

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modwevtapi    = syscall.NewLazyDLL("wevtapi.dll")
	procEvtQuery  = modwevtapi.NewProc("EvtQuery")
	procEvtNext   = modwevtapi.NewProc("EvtNext")
	procEvtRender = modwevtapi.NewProc("EvtRender")
	procEvtClose  = modwevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	errAccessDeniedCode      = 5
	errNoMoreItemsCode       = 259
	maxLogonEvents           = 20000
)

// RecentLogons reads failed logons (4625) and successful logons (4624) from the
// Security log for the last `hours`. Reading that log needs administrator
// rights; without them the result says so instead of failing the scan.
func RecentLogons(hours int) Logons {
	ms := hours * 3600 * 1000
	query := fmt.Sprintf(`*[System[(EventID=4625 or EventID=4624) and TimeCreated[timediff(@SystemTime) <= %d]]]`, ms)
	ch, _ := syscall.UTF16PtrFromString("Security")
	q, _ := syscall.UTF16PtrFromString(query)
	rs, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)),
		evtQueryChannelPath|evtQueryReverseDirection)
	if rs == 0 {
		if errno, ok := e.(syscall.Errno); ok && errno == errAccessDeniedCode {
			return Logons{Reason: "needs administrator rights to read the Security log", Hours: hours}
		}
		return Logons{Reason: "Security log query failed: " + e.Error(), Hours: hours}
	}
	defer procEvtClose.Call(rs)

	var events []LogonEvent
	handles := make([]uintptr, 64)
	buf := make([]uint16, 8192)
	truncated := false
	for len(events) < maxLogonEvents {
		var n uint32
		r, _, _ := procEvtNext.Call(rs, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), 5000, 0,
			uintptr(unsafe.Pointer(&n)))
		if r == 0 || n == 0 {
			break
		}
		for _, h := range handles[:n] {
			var used, props uint32
			ok, _, _ := procEvtRender.Call(0, h, evtRenderEventXML, uintptr(len(buf)*2),
				uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
			if ok == 0 && used > uint32(len(buf)*2) {
				buf = make([]uint16, used/2+1)
				ok, _, _ = procEvtRender.Call(0, h, evtRenderEventXML, uintptr(len(buf)*2),
					uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
			}
			procEvtClose.Call(h)
			if ok == 0 {
				continue
			}
			if ev, err := ParseLogonEventXML([]byte(syscall.UTF16ToString(buf[:used/2]))); err == nil {
				events = append(events, ev)
			}
		}
	}
	if len(events) >= maxLogonEvents {
		truncated = true
	}
	s := SummariseLogons(events, hours)
	s.Truncated = truncated
	return s
}
