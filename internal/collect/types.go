// Package collect reads raw host state: processes, TCP endpoints, the DNS cache,
// Authenticode signatures and token elevation. It never touches the network.
package collect

import (
	"fmt"
	"net/netip"
	"time"
)

// Process is a point-in-time view of one process. Name, Path and Cmdline come
// from the process itself and must be treated as attacker-controlled text.
type Process struct {
	PID, PPID uint32
	Name      string
	Path      string
	Cmdline   string
	Created   time.Time // zero when unreadable
	PathErr   error
	CmdErr    error
}

// TCPState mirrors MIB_TCP_STATE.
type TCPState uint32

const (
	StateListen      TCPState = 2
	StateEstablished TCPState = 5
)

var tcpStateNames = [...]string{"", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
	"FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"}

func (s TCPState) String() string {
	if int(s) < len(tcpStateNames) && s > 0 {
		return tcpStateNames[s]
	}
	return fmt.Sprintf("STATE(%d)", uint32(s))
}

// TCPConn is one row of the system TCP table with its owning process.
type TCPConn struct {
	Local, Remote netip.AddrPort
	State         TCPState
	PID           uint32
}

// SigStatus is the Authenticode verdict for an executable.
type SigStatus string

const (
	SigSigned   SigStatus = "signed"
	SigPackage  SigStatus = "package"  // inside an installed MSIX package (verified at install, TrustedInstaller-owned)
	SigUnsigned SigStatus = "unsigned" // no embedded signature and no catalog entry
	SigInvalid  SigStatus = "invalid"  // signature present but fails: tampered, untrusted root, distrusted
	SigError    SigStatus = "error"    // could not check (file unreadable, API error)
	SigRemote   SigStatus = "remote"   // on a network share or mapped drive: deliberately not opened
)

// DetailNotFullPath is the SigError detail for a bare or relative name. Which
// file runs depends on PATH or a working directory — PATH includes the
// user-writable %LOCALAPPDATA%\Microsoft\WindowsApps — so it rates medium.
const DetailNotFullPath = "not a full local path; not opened"

// Signature is the result of verifying one file.
type Signature struct {
	Status  SigStatus `json:"status"`
	Signer  string    `json:"signer,omitempty"`
	Catalog bool      `json:"catalog,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}
