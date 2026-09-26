// Package render turns a snapshot into human-readable text. Every host string
// passes through clean() first: redacted, stripped of hidden characters, truncated.
package render

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/co2water/agentegress/internal/agents"
	"github.com/co2water/agentegress/internal/collect"
	"github.com/co2water/agentegress/internal/engine"
	"github.com/co2water/agentegress/internal/snapshot"
)

// Options control how much is printed.
type Options struct {
	Verbose bool // every process in agent trees, not only interesting ones
}

// Text writes the scan report.
func Text(w io.Writer, s *snapshot.Snapshot, rep *engine.Report, o Options) {
	r := &report{w: w, s: s, o: o, conns: map[uint32][]snapshot.Conn{}}
	for _, c := range s.Conns {
		owner := r.displayOwner(c.PID)
		r.conns[owner] = append(r.conns[owner], c)
	}
	r.header()
	if rep != nil {
		r.findings(rep)
	}
	r.agents()
	r.others()
	r.listeners()
	r.mcpInventory()
	r.footer()
}

type report struct {
	w     io.Writer
	s     *snapshot.Snapshot
	o     Options
	conns map[uint32][]snapshot.Conn // keyed by display owner (helpers folded into their agent)
}

func (r *report) printf(format string, a ...any) { fmt.Fprintf(r.w, format, a...) }

// displayOwner folds a helper process into the nearest non-helper ancestor.
func (r *report) displayOwner(pid uint32) uint32 {
	for p := r.s.Procs[pid]; p != nil && p.Helper && p.Parent != 0; p = r.s.Procs[p.Parent] {
		pid = p.Parent
	}
	return pid
}

func (r *report) header() {
	priv := "not elevated"
	if r.s.Elevated {
		priv = "elevated"
	}
	r.printf("agentegress scan · %s · %s · %v\n", r.s.Time.Format("2006-01-02 15:04:05"), priv, r.s.Took.Round(time.Millisecond))
	c := r.s.Coverage
	r.printf("Saw %d processes (%d unreadable), %d cached DNS addresses.\n", c.Processes, c.Unreadable, c.DNSNames)
	for _, l := range c.Limits {
		r.printf("  limit: %s\n", l)
	}
}

func (r *report) agents() {
	var agentsN, mcpN int
	for _, p := range r.s.Procs {
		if p.Agent != "" && !p.Helper {
			agentsN++
		}
		if p.MCP != "" {
			mcpN++
		}
	}
	r.printf("\nAI AGENTS  %d root(s), %d agent process(es), %d MCP process(es)\n", len(r.s.Roots), agentsN, mcpN)
	if len(r.s.Roots) == 0 {
		r.printf("  none running\n")
		return
	}
	for _, root := range r.s.Roots {
		p := r.s.Procs[root]
		r.printf("\n■ %s  pid %d  %s\n", p.Agent, root, badge(p))
		r.printf("   %s\n", clean(p.Path, 100))
		r.connLines("   ", root)
		r.tree(root, "   ")
	}
}

func (r *report) tree(pid uint32, indent string) {
	for _, c := range r.s.Procs[pid].Children {
		p := r.s.Procs[c]
		if p.Helper {
			// Helpers are folded into their agent, but their children still count.
			r.tree(c, indent)
			continue
		}
		if !r.o.Verbose && !r.interesting(c, map[uint32]bool{}) {
			continue
		}
		label := clean(p.Name, 40)
		switch {
		case p.Agent != "":
			label = string(p.Agent) + "  " + label
		case p.MCP == "?":
			label = "MCP?  " + label
		case p.MCP != "":
			label = "MCP " + clean(p.MCP, 40) + "  " + label
		}
		r.printf("%s├─ %s  pid %d  %s\n", indent, label, c, badge(p))
		if p.Agent == "" {
			r.printf("%s│    %s\n", indent, clean(p.Cmdline, 100))
		}
		r.connLines(indent+"│    ", c)
		r.tree(c, indent+"│  ")
	}
}

// interesting keeps the tree readable: agents, MCP servers and anything with a
// non-loopback connection or listener, plus the ancestors needed to reach them.
func (r *report) interesting(pid uint32, seen map[uint32]bool) bool {
	if seen[pid] {
		return false
	}
	seen[pid] = true
	p := r.s.Procs[pid]
	if (p.Agent != "" && !p.Helper) || p.MCP != "" {
		return true
	}
	for _, c := range r.conns[r.displayOwner(pid)] {
		if (c.External || c.Exposed) && r.displayOwner(pid) == pid {
			return true
		}
	}
	for _, ch := range p.Children {
		if r.interesting(ch, seen) {
			return true
		}
	}
	return false
}

func (r *report) connLines(indent string, pid uint32) {
	var lines []string
	loopback := 0
	for _, c := range r.conns[pid] {
		switch {
		case c.Exposed:
			lines = append(lines, "LISTEN "+c.Local+"  ⚠ reachable from the network")
		case c.External:
			lines = append(lines, "→ "+peer(c))
		case c.State == "ESTABLISHED":
			loopback++
		}
	}
	slices.Sort(lines)
	lines = slices.Compact(lines)
	for _, l := range lines {
		r.printf("%s%s\n", indent, l)
	}
	if loopback > 0 && r.o.Verbose {
		r.printf("%s(+%d loopback)\n", indent, loopback)
	}
}

func peer(c snapshot.Conn) string {
	org := ""
	if c.Org != "" {
		org = "  [" + c.Org + "]"
	}
	if len(c.Hosts) == 0 {
		if org == "" {
			return c.Remote + "  (unknown owner)"
		}
		return c.Remote + org
	}
	h := clean(c.Hosts[0], 60)
	if len(c.Hosts) > 1 {
		h += fmt.Sprintf(" +%d", len(c.Hosts)-1)
	}
	return h + "  " + c.Remote + org
}

// peerShort names a peer for the one-line tables.
func peerShort(c snapshot.Conn) string {
	switch {
	case len(c.Hosts) > 0:
		return clean(c.Hosts[0], 50)
	case c.Org != "":
		return c.Org
	}
	return c.Remote
}

func (r *report) others() {
	type row struct {
		pid   uint32
		peers []string
	}
	byPID := map[uint32]*row{}
	for _, c := range r.s.Conns {
		p := r.s.Procs[c.PID]
		if !c.External || (p != nil && p.Root != 0) {
			continue
		}
		if byPID[c.PID] == nil {
			byPID[c.PID] = &row{pid: c.PID}
		}
		byPID[c.PID].peers = append(byPID[c.PID].peers, peerShort(c))
	}
	rows := make([]*row, 0, len(byPID))
	for _, x := range byPID {
		slices.Sort(x.peers)
		x.peers = slices.Compact(x.peers)
		rows = append(rows, x)
	}
	sort.Slice(rows, func(i, j int) bool { return procName(r.s, rows[i].pid) < procName(r.s, rows[j].pid) })

	r.printf("\nOTHER PROCESSES WITH EXTERNAL CONNECTIONS  %d\n", len(rows))
	tw := tabwriter.NewWriter(r.w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  PROCESS\tPID\tSIGNATURE\tPEERS\n")
	for _, x := range rows {
		peers := strings.Join(x.peers[:min(3, len(x.peers))], ", ")
		if len(x.peers) > 3 {
			peers += fmt.Sprintf(" +%d", len(x.peers)-3)
		}
		fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\n", procName(r.s, x.pid), x.pid, badge(r.s.Procs[x.pid]), peers)
	}
	tw.Flush()
}

func (r *report) listeners() {
	addrs := map[uint32][]string{}
	var pids []uint32
	for _, c := range r.s.Conns {
		if !c.Exposed {
			continue
		}
		if addrs[c.PID] == nil {
			pids = append(pids, c.PID)
		}
		addrs[c.PID] = append(addrs[c.PID], c.Local)
	}
	slices.Sort(pids)
	r.printf("\nLISTENING ON NETWORK INTERFACES  %d process(es)\n", len(pids))
	tw := tabwriter.NewWriter(r.w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  PROCESS\tPID\tSIGNATURE\tAGENT TREE\tADDRESSES\n")
	for _, pid := range pids {
		p := r.s.Procs[pid]
		tree := ""
		if p != nil && p.Root != 0 {
			tree = string(p.Owner)
		}
		a := addrs[pid]
		list := strings.Join(a[:min(4, len(a))], ", ")
		if len(a) > 4 {
			list += fmt.Sprintf(" +%d", len(a)-4)
		}
		fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\t%s\n", procName(r.s, pid), pid, badge(p), tree, list)
	}
	tw.Flush()
}

func (r *report) mcpInventory() {
	running := map[string]int{}
	for _, p := range r.s.Procs {
		if p.MCP != "" && p.MCP != "?" {
			running[string(p.MCPClient)+"|"+p.MCP]++
		}
	}
	servers := slices.Clone(r.s.MCPServers)
	slices.SortFunc(servers, func(a, b agents.MCPServer) int {
		return strings.Compare(string(a.Client)+a.Name, string(b.Client)+b.Name)
	})
	r.printf("\nMCP SERVERS IN CONFIG  %d\n", len(servers))
	tw := tabwriter.NewWriter(r.w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  CLIENT\tNAME\tSTATE\tLAUNCH\n")
	for _, m := range servers {
		state := "not running"
		if n := running[string(m.Client)+"|"+m.Name]; n > 0 {
			state = fmt.Sprintf("running ×%d", n)
		}
		launch := m.URL
		if launch == "" {
			launch = strings.TrimSpace(m.Command + " " + strings.Join(m.Args, " "))
		}
		if len(m.EnvKeys) > 0 {
			launch += fmt.Sprintf("  [env: %s]", strings.Join(m.EnvKeys, ", "))
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", m.Client, clean(m.Name, 30), state, clean(launch, 80))
	}
	tw.Flush()
}

func (r *report) footer() {
	for _, w := range r.s.Warnings {
		r.printf("\nwarning: %s", clean(w, 200))
	}
	if len(r.s.Warnings) > 0 {
		r.printf("\n")
	}
}

func procName(s *snapshot.Snapshot, pid uint32) string {
	if p := s.Procs[pid]; p != nil {
		return clean(p.Name, 40)
	}
	return "?"
}

func sig(s *collect.Signature) string {
	if s == nil {
		return "·"
	}
	switch s.Status {
	case collect.SigSigned:
		if s.Signer != "" {
			return "✓ " + clean(s.Signer, 40)
		}
		return "✓ signed"
	case collect.SigPackage:
		return "◇ store package"
	case collect.SigUnsigned:
		return "✗ unsigned"
	case collect.SigInvalid:
		return "‼ invalid signature: " + s.Detail
	default:
		return "? " + s.Detail
	}
}

// badge summarises what we know about a process binary. The user-writable
// note only appears when the binary is not signed, where it matters.
func badge(p *snapshot.Proc) string {
	switch {
	case p == nil:
		return "?"
	case !p.Readable:
		return "— no access (needs admin)"
	case p.Signature == nil:
		return "·"
	}
	b := sig(p.Signature)
	if p.UserDir && p.Signature.Status != collect.SigSigned && p.Signature.Status != collect.SigPackage {
		b += " · in user-writable dir"
	}
	return b
}

func clean(s string, limit int) string {
	return agents.Sanitize(agents.Redact(strings.TrimSpace(s)), limit)
}
