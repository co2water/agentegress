// Package snapshot joins raw host state into one model: a validated process
// tree, agent roots, MCP attribution, named connections and signatures. The
// rule engine (W2) and every output format read this model and nothing else.
package snapshot

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/co2water/agentegress/internal/agents"
	"github.com/co2water/agentegress/internal/collect"
	"github.com/co2water/agentegress/internal/ipowner"
)

// Proc is one process in the model. Name, Path and Cmdline are raw host text.
type Proc struct {
	PID       uint32             `json:"pid"`
	PPID      uint32             `json:"ppid"`
	Name      string             `json:"name"`
	Path      string             `json:"path,omitempty"`
	Cmdline   string             `json:"cmdline,omitempty"`
	Created   time.Time          `json:"created,omitzero"`
	Readable  bool               `json:"readable"`
	Agent     agents.Kind        `json:"agent,omitempty"`      // this process is an agent
	Helper    bool               `json:"helper,omitempty"`     // Electron-style helper of its parent agent
	Root      uint32             `json:"agent_root,omitempty"` // top-most agent above (or equal to) this process
	Owner     agents.Kind        `json:"owner,omitempty"`      // nearest agent at or above this process
	MCP       string             `json:"mcp,omitempty"`        // matched server name, or "?" when it only looks like one
	MCPClient agents.Kind        `json:"mcp_client,omitempty"` // client whose config defines MCP
	UserDir   bool               `json:"user_writable_dir,omitempty"`
	Signature *collect.Signature `json:"signature,omitempty"`
	// Payload is the file a script host (rundll32, wscript, powershell -File,
	// ...) was told to run; its signature is what matters, not the host's.
	Payload          string             `json:"payload,omitempty"`
	PayloadUserDir   bool               `json:"payload_user_writable_dir,omitempty"`
	PayloadSignature *collect.Signature `json:"payload_signature,omitempty"`
	// UpdatedTo is set when the program's file was renamed aside by an
	// updater ("x.exe.old.123"): the file now at the original path, which the
	// renamed one was replaced with, and its signature.
	UpdatedTo          string             `json:"updated_to,omitempty"`
	UpdatedToSignature *collect.Signature `json:"updated_to_signature,omitempty"`
	Children           []uint32           `json:"-"`
	Parent             uint32             `json:"parent,omitempty"` // validated parent, 0 when none
}

// Conn is one TCP endpoint with names attached.
type Conn struct {
	PID      uint32   `json:"pid"`
	State    string   `json:"state"`
	Local    string   `json:"local"`
	Remote   string   `json:"remote,omitempty"`
	Hosts    []string `json:"hosts,omitempty"`    // from the DNS cache; empty when unknown
	Org      string   `json:"org,omitempty"`      // owner of the published IP range; empty when unknown
	External bool     `json:"external,omitempty"` // established to a non-loopback peer
	Exposed  bool     `json:"exposed,omitempty"`  // listening on a non-loopback interface
}

// Coverage says how much of the host the scan could see.
type Coverage struct {
	Processes      int      `json:"processes"`
	Unreadable     int      `json:"unreadable"`
	AgentTree      int      `json:"agent_tree_processes"`
	AgentTreeBlind int      `json:"agent_tree_unreadable"`
	DNSNames       int      `json:"dns_cached_addresses"`
	Limits         []string `json:"limits"`
}

// Autostart is a persistence entry with what we learned about its target.
type Autostart struct {
	collect.Autostart
	Signature *collect.Signature `json:"signature,omitempty"`
	UserDir   bool               `json:"user_writable_dir,omitempty"`
	// The host program (rundll32, cmd, node, ...) is judged too: a renamed fake
	// host in a user folder must not hide behind the file it loads.
	HostSignature *collect.Signature `json:"host_signature,omitempty"`
	HostUserDir   bool               `json:"host_user_writable_dir,omitempty"`
}

// Snapshot is the whole model for one scan.
type Snapshot struct {
	Time       time.Time          `json:"time"`
	Elevated   bool               `json:"elevated"`
	Took       time.Duration      `json:"took_ns"`
	Coverage   Coverage           `json:"coverage"`
	Roots      []uint32           `json:"agent_roots"`
	Procs      map[uint32]*Proc   `json:"processes"`
	Conns      []Conn             `json:"connections"`
	MCPServers []agents.MCPServer `json:"mcp_servers"`
	Autostarts []Autostart        `json:"autostarts"`
	Host       collect.HostConfig `json:"host"`
	Logons     collect.Logons     `json:"logons"`
	Warnings   []string           `json:"warnings,omitempty"`
}

// Input is everything the collectors produced.
type Input struct {
	Procs      map[uint32]*collect.Process
	Conns      []collect.TCPConn
	DNS        map[netip.Addr][]string
	Servers    []agents.MCPServer
	Autostarts []collect.Autostart
	Host       collect.HostConfig
	Logons     collect.Logons
	Elevated   bool
	UserDirs   []string // lower-case prefixes that ordinary users can write to (used when UserWritable is nil)
	// UserWritable reports whether a standard user could have placed or
	// replaced the file. The live scan passes a check that treats every folder
	// not known to be admin-only as writable; fixtures use UserDirs.
	UserWritable func(path string) bool
}

// Verifier checks signatures for a set of paths.
type Verifier func(paths []string) map[string]collect.Signature

// Build assembles the model. verify is called once with the paths that matter:
// every process in an agent tree and every process with an external connection
// or exposed listener.
func Build(in Input, verify Verifier) *Snapshot {
	s := &Snapshot{Time: time.Now(), Elevated: in.Elevated, Procs: map[uint32]*Proc{}, MCPServers: in.Servers,
		Host: in.Host, Logons: in.Logons}
	writable := in.UserWritable
	if writable == nil {
		writable = func(p string) bool { return underAny(p, in.UserDirs) }
	}
	for _, a := range in.Autostarts {
		s.Autostarts = append(s.Autostarts, Autostart{Autostart: a, UserDir: writable(a.Target),
			HostUserDir: a.Host != "" && writable(a.Host)})
	}

	for pid, p := range in.Procs {
		s.Procs[pid] = &Proc{
			PID: pid, PPID: p.PPID, Name: p.Name, Path: p.Path, Cmdline: p.Cmdline, Created: p.Created,
			Readable: p.PathErr == nil,
			Agent:    agents.Classify(p.Name, p.Path, p.Cmdline),
			UserDir:  p.Path != "" && writable(p.Path),
		}
		if pl := collect.Payload(p.Cmdline, p.Path); pl != "" {
			s.Procs[pid].Payload = pl
			s.Procs[pid].PayloadUserDir = writable(pl)
		}
	}
	s.link()
	s.markHelpers()
	s.assignRoots()
	s.attributeMCP()
	s.addConns(in.Conns, in.DNS)
	s.coverage(len(in.DNS))
	s.sign(verify)
	return s
}

// link builds parent/child edges, refusing edges where the "parent" was created
// after the child: that parent PID has been reused by an unrelated process.
func (s *Snapshot) link() {
	for pid, p := range s.Procs {
		parent, ok := s.Procs[p.PPID]
		if !ok || p.PPID == pid || p.PPID == 0 {
			continue
		}
		if !parent.Created.IsZero() && !p.Created.IsZero() && parent.Created.After(p.Created) {
			continue
		}
		// Review finding #10: an unreadable child (no creation time) under a
		// readable parent cannot be checked for PID reuse, so do not attribute
		// it — an unrelated orphan must not land in an agent's tree. When both
		// are unreadable (system processes) the link carries no attribution risk.
		if p.Created.IsZero() && !parent.Created.IsZero() {
			continue
		}
		p.Parent = p.PPID
		parent.Children = append(parent.Children, pid)
	}
	for _, p := range s.Procs {
		slices.Sort(p.Children)
	}
}

func (s *Snapshot) markHelpers() {
	for _, p := range s.Procs {
		if p.Agent == "" || p.Parent == 0 {
			continue
		}
		if parent := s.Procs[p.Parent]; parent.Agent == p.Agent && strings.Contains(p.Cmdline, "--type=") {
			p.Helper = true
		}
	}
}

func (s *Snapshot) assignRoots() {
	for pid, p := range s.Procs {
		if p.Agent == "" {
			continue
		}
		top := true
		seen := map[uint32]bool{pid: true}
		for cur := p.Parent; cur != 0 && !seen[cur]; cur = s.Procs[cur].Parent {
			seen[cur] = true
			if s.Procs[cur].Agent != "" {
				top = false
				break
			}
		}
		if top {
			s.Roots = append(s.Roots, pid)
		}
	}
	slices.Sort(s.Roots)
	for _, r := range s.Roots {
		s.descend(r, r, s.Procs[r].Agent, map[uint32]bool{})
	}
}

func (s *Snapshot) descend(pid, root uint32, owner agents.Kind, seen map[uint32]bool) {
	if seen[pid] {
		return
	}
	seen[pid] = true
	p := s.Procs[pid]
	if p.Agent != "" {
		owner = p.Agent
	}
	p.Root, p.Owner = root, owner
	for _, c := range p.Children {
		s.descend(c, root, owner, seen)
	}
}

func (s *Snapshot) attributeMCP() {
	for _, p := range s.Procs {
		if p.Root == 0 || p.Agent != "" {
			continue
		}
		if i := agents.MatchServer(s.MCPServers, p.Cmdline, p.Owner); i >= 0 {
			p.MCP, p.MCPClient = s.MCPServers[i].Name, s.MCPServers[i].Client
		} else if agents.LooksLikeMCP(p.Cmdline) {
			p.MCP = "?"
		}
	}
}

func isLocal(a netip.Addr) bool { return a.IsLoopback() || a.IsUnspecified() }

func (s *Snapshot) addConns(conns []collect.TCPConn, dns map[netip.Addr][]string) {
	for _, c := range conns {
		out := Conn{PID: c.PID, State: c.State.String(), Local: c.Local.String()}
		switch c.State {
		case collect.StateListen:
			out.Exposed = !c.Local.Addr().IsLoopback()
		default:
			out.Remote = c.Remote.String()
			out.External = c.State == collect.StateEstablished && !isLocal(c.Remote.Addr())
			out.Hosts = dns[c.Remote.Addr()]
			if out.External {
				out.Org = ipowner.Lookup(c.Remote.Addr())
			}
		}
		s.Conns = append(s.Conns, out)
	}
	slices.SortFunc(s.Conns, func(a, b Conn) int {
		if a.PID != b.PID {
			return int(a.PID) - int(b.PID)
		}
		return strings.Compare(a.Remote+a.Local, b.Remote+b.Local)
	})
}

func (s *Snapshot) coverage(dnsNames int) {
	c := &s.Coverage
	for pid, p := range s.Procs {
		if pid == 0 || pid == 4 {
			continue
		}
		c.Processes++
		if !p.Readable {
			c.Unreadable++
		}
		if p.Root != 0 {
			c.AgentTree++
			if !p.Readable {
				c.AgentTreeBlind++
			}
		}
	}
	c.DNSNames = dnsNames
	c.Limits = append(c.Limits, "TCP only: UDP/QUIC (HTTP/3) peers are not visible")
	if !s.Elevated && c.Unreadable > 0 {
		c.Limits = append(c.Limits, "not elevated: processes of other users and system services are unreadable")
	}
	if !s.Elevated {
		c.Limits = append(c.Limits, "not elevated: only scheduled tasks visible to this user are listed")
	}
	if !s.Logons.Checked && s.Logons.Reason != "" {
		c.Limits = append(c.Limits, "logon history not checked: "+s.Logons.Reason)
	}
}

func (s *Snapshot) sign(verify Verifier) {
	if verify == nil {
		return
	}
	want := map[uint32]bool{}
	for pid, p := range s.Procs {
		if p.Root != 0 {
			want[pid] = true
		}
	}
	for _, c := range s.Conns {
		if c.External || c.Exposed {
			want[c.PID] = true
		}
	}
	var paths []string
	for pid := range want {
		if p := s.Procs[pid]; p != nil && p.Path != "" {
			paths = append(paths, p.Path)
			if p.Payload != "" && (!collect.IsScriptFile(p.Payload) || collect.JudgeScriptPayload(p.Path)) {
				paths = append(paths, p.Payload)
			}
			if cur := updatedImage(p.Path); cur != "" {
				paths = append(paths, cur)
			}
		}
	}
	skipped := 0
	for _, a := range s.Autostarts {
		// Hundreds of services and tasks point into System32; verifying their
		// catalog signatures dominated scan time. Replacing a file there needs
		// administrator or TrustedInstaller rights, at which point the attacker
		// can defeat this tool anyway, so they are not checked (and say so).
		for _, f := range []string{a.Target, a.Host} {
			switch {
			case f == "":
			case collect.ProtectedSystemPath(f):
				skipped++
			default:
				paths = append(paths, f)
			}
		}
	}
	if skipped > 0 {
		s.Coverage.Limits = append(s.Coverage.Limits, fmt.Sprintf(
			"%d autostart files inside System32/SysWOW64 were not signature-checked (only administrators can change files there)", skipped))
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	sigs := verify(paths)
	for pid := range want {
		if p := s.Procs[pid]; p != nil {
			if sig, ok := sigs[p.Path]; ok {
				p.Signature = &sig
			}
			if sig, ok := sigs[p.Payload]; ok && p.Payload != "" {
				p.PayloadSignature = &sig
			}
			if cur := updatedImage(p.Path); cur != "" {
				if sig, ok := sigs[cur]; ok {
					p.UpdatedTo, p.UpdatedToSignature = cur, &sig
				}
			}
		}
	}
	for i := range s.Autostarts {
		if h := s.Autostarts[i].Host; h != "" {
			if sig, ok := sigs[h]; ok {
				s.Autostarts[i].HostSignature = &sig
			}
		}
		if sig, ok := sigs[s.Autostarts[i].Target]; ok {
			s.Autostarts[i].Signature = &sig
		}
	}
}

// oldImage matches a running program's file that an updater renamed aside
// ("claude.exe.old.1790342555531") before writing the new version in place.
var oldImage = regexp.MustCompile(`(?i)^(.+\.exe)\.old\.[0-9]+$`)

// updatedImage returns the path a renamed-aside program was replaced at, or "".
func updatedImage(path string) string {
	if m := oldImage.FindStringSubmatch(path); m != nil {
		return m[1]
	}
	return ""
}

func underAny(path string, dirs []string) bool {
	p := strings.ToLower(filepath.Clean(path))
	for _, d := range dirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}
