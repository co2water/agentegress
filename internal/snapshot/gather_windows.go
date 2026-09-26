//go:build windows

package snapshot

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/co2water/agentegress/internal/agents"
	"github.com/co2water/agentegress/internal/collect"
)

// LogonHours is how far back the Security log is read.
const LogonHours = 24

// Gather runs every collector on this machine and builds the model. A collector
// that panics (for example on a crafted file an attacker planted to crash the
// scanner) is skipped and reported as not checked; the rest of the scan runs.
func Gather() (*Snapshot, error) {
	start := time.Now()

	var (
		mu     sync.Mutex
		failed []string
	)
	guard := func(what string, f func()) {
		defer func() {
			if r := recover(); r != nil {
				mu.Lock()
				failed = append(failed, fmt.Sprintf("%s: collector crashed and was skipped (%v)", what, r))
				mu.Unlock()
			}
		}()
		f()
	}

	// Host-level collectors (autostarts spawn schtasks, logons read the event
	// log) are independent of the process view, so run them alongside it.
	var (
		wg         sync.WaitGroup
		autostarts []collect.Autostart
		autoNotes  []string
		host       collect.HostConfig
		logons     collect.Logons
	)
	wg.Add(3)
	go func() { defer wg.Done(); guard("autostarts", func() { autostarts, autoNotes = collect.Autostarts() }) }()
	go func() { defer wg.Done(); guard("host settings", func() { host = collect.HostSettings() }) }()
	go func() {
		defer wg.Done()
		logons = collect.Logons{Reason: "collector crashed", Hours: LogonHours}
		guard("logons", func() { logons = collect.RecentLogons(LogonHours) })
	}()

	var (
		procs map[uint32]*collect.Process
		conns []collect.TCPConn
		err   error
	)
	guard("processes", func() { procs, err = collect.Processes() })
	if err == nil && procs == nil {
		err = errors.New("process collector crashed")
	}
	if err != nil {
		wg.Wait()
		return nil, err
	}
	guard("tcp", func() { conns, err = collect.TCPConnections() })
	if err != nil {
		wg.Wait()
		return nil, err
	}
	var warnings []string
	var dns map[netip.Addr][]string
	guard("dns cache", func() {
		d, derr := collect.DNSNames()
		if derr != nil {
			warnings = append(warnings, "DNS cache unavailable, connections will show addresses only: "+derr.Error())
		}
		dns = d
	})
	var servers []agents.MCPServer
	guard("mcp configs", func() {
		var w []string
		d := agents.DirsFromEnv()
		d.Remote = collect.IsRemotePath
		servers, w = agents.Inventory(d)
		warnings = append(warnings, w...)
	})
	wg.Wait()
	warnings = append(warnings, autoNotes...)

	var s *Snapshot
	guard("model", func() {
		s = Build(Input{
			Procs:      procs,
			Conns:      conns,
			DNS:        dns,
			Servers:    servers,
			Autostarts: autostarts,
			Host:       host,
			Logons:     logons,
			Elevated:   collect.Elevated(),
			// Only local paths are placed in a folder; a bare name or a share
			// is judged by its own signature status instead.
			UserWritable: func(p string) bool { return p != "" && !collect.IsRemotePath(p) && !collect.AdminOnlyPath(p) },
		}, collect.VerifyFiles)
	})
	if s == nil {
		return nil, fmt.Errorf("building the model failed: %v", failed)
	}
	s.Warnings = append(s.Warnings, warnings...)
	s.Warnings = append(s.Warnings, failed...)
	s.Coverage.Limits = append(s.Coverage.Limits, failed...)
	s.Coverage.Limits = append(s.Coverage.Limits, autoNotes...) // e.g. tasks that could not be read

	// The tool promises it never opens a connection. Check after signature
	// verification, the only step that could plausibly try (it is configured
	// for cache-only retrieval). This sees TCP endpoints alive at this moment,
	// not UDP or short-lived connections, so it is a tripwire, not a proof.
	self := uint32(os.Getpid())
	var after []collect.TCPConn
	guard("self-check", func() { after, _ = collect.TCPConnections() })
	for _, c := range append(conns, after...) {
		if c.PID == self {
			s.Warnings = append(s.Warnings, "agentegress itself owns a TCP endpoint ("+c.Local.String()+"): this should never happen, please report it")
			break
		}
	}
	s.Took = time.Since(start)
	return s, nil
}
