package snapshot

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/co2water/agentegress/internal/collect"
)

// Third code review (2026-09-26): the model must verify the files the engine
// now judges, and pass through the writable-folder check it is given.
func TestThirdReviewSigning(t *testing.T) {
	wscript := `C:\Windows\System32\wscript.exe`
	script := `C:\Users\alice\u.js`
	old := `C:\Users\alice\npm\claude.exe.old.1790342555531`
	current := `C:\Users\alice\npm\claude.exe`
	ext := func(pid uint32) collect.TCPConn {
		return collect.TCPConn{PID: pid, State: collect.StateEstablished,
			Local: netip.MustParseAddrPort("192.168.1.50:50000"), Remote: netip.MustParseAddrPort("203.0.113.5:443")}
	}
	in := Input{
		Procs: map[uint32]*collect.Process{
			1:  proc(1, 0, "explorer.exe", `C:\Windows\explorer.exe`, "explorer", 0),
			30: proc(30, 1, "wscript.exe", wscript, `wscript.exe `+script, time.Minute),
			31: proc(31, 1, "claude.exe", old, `"`+current+`"`, time.Minute),
			32: proc(32, 1, "tool.exe", `D:\tools\tool.exe`, `D:\tools\tool.exe`, time.Minute),
		},
		Conns: []collect.TCPConn{ext(30), ext(31), ext(32)},
		UserWritable: func(p string) bool {
			return !strings.HasPrefix(strings.ToLower(p), `c:\windows\`)
		},
	}
	var asked []string
	s := Build(in, func(paths []string) map[string]collect.Signature {
		asked = paths
		out := map[string]collect.Signature{}
		for _, p := range paths {
			out[p] = collect.Signature{Status: collect.SigSigned}
		}
		return out
	})
	for _, want := range []string{script, current} {
		if !slices.Contains(asked, want) {
			t.Errorf("%s was not verified; asked for %v", want, asked)
		}
	}
	if p := s.Procs[30]; p.Payload != script || p.PayloadSignature == nil || !p.PayloadUserDir || p.UserDir {
		t.Errorf("wscript proc = %+v", p)
	}
	if p := s.Procs[31]; p.UpdatedTo != current || p.UpdatedToSignature == nil {
		t.Errorf("renamed-aside proc = %+v", p)
	}
	if !s.Procs[32].UserDir {
		t.Error("D:\\tools not treated as user-writable")
	}
}
