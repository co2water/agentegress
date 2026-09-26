package snapshot

import (
	"github.com/co2water/agentegress/internal/agents"
	"github.com/co2water/agentegress/internal/collect"
)

// Redacted returns a copy safe to hand to other tools or an LLM: credentials in
// host text are masked and invisible or control characters stripped. Nothing
// is truncated. Every string field that came from the host goes through clean;
// TestRedactedCoversEveryHostString checks the fields its fixture marks (it is
// not reflective, so a new host field needs a marker there too).
func Redacted(s *Snapshot) *Snapshot {
	out := *s
	out.Procs = make(map[uint32]*Proc, len(s.Procs))
	for pid, p := range s.Procs {
		c := *p
		c.Name = clean(c.Name)
		c.Path = clean(c.Path)
		c.Cmdline = clean(c.Cmdline)
		c.MCP = clean(c.MCP)
		c.Payload = clean(c.Payload)
		c.Signature = cleanSig(c.Signature)
		c.PayloadSignature = cleanSig(c.PayloadSignature)
		c.UpdatedTo = clean(c.UpdatedTo)
		c.UpdatedToSignature = cleanSig(c.UpdatedToSignature)
		out.Procs[pid] = &c
	}
	out.Conns = make([]Conn, len(s.Conns))
	for i, c := range s.Conns {
		c.Hosts = cleanAll(c.Hosts)
		out.Conns[i] = c
	}
	out.MCPServers = make([]agents.MCPServer, len(s.MCPServers))
	for i, m := range s.MCPServers {
		m.Name = clean(m.Name)
		m.Source = clean(m.Source)
		m.Command = clean(m.Command)
		m.URL = clean(m.URL)
		m.Args = cleanAll(m.Args)
		m.EnvKeys = cleanAll(m.EnvKeys)
		out.MCPServers[i] = m
	}
	out.Autostarts = make([]Autostart, len(s.Autostarts))
	for i, a := range s.Autostarts {
		a.Name = clean(a.Name)
		a.Location = clean(a.Location)
		a.Command = clean(a.Command)
		a.Target = clean(a.Target)
		a.Host = clean(a.Host)
		a.Signature = cleanSig(a.Signature)
		a.HostSignature = cleanSig(a.HostSignature) // third review, item 16
		out.Autostarts[i] = a
	}
	out.Logons = s.Logons
	out.Logons.Failed = cleanSources(s.Logons.Failed)
	out.Logons.RemoteDesk = cleanSources(s.Logons.RemoteDesk)
	out.Warnings = cleanAll(s.Warnings)
	out.Coverage.Limits = cleanAll(s.Coverage.Limits) // may quote collector errors
	return &out
}

func clean(s string) string { return agents.Sanitize(agents.Redact(s), 0) }

func cleanAll(v []string) []string {
	if v == nil {
		return nil
	}
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = clean(s)
	}
	return out
}

func cleanSig(s *collect.Signature) *collect.Signature {
	if s == nil {
		return nil
	}
	c := *s
	c.Signer = clean(c.Signer)
	return &c
}

func cleanSources(v []collect.LogonSource) []collect.LogonSource {
	if v == nil {
		return nil
	}
	out := make([]collect.LogonSource, len(v))
	for i, s := range v {
		s.IP = clean(s.IP)
		s.Users = cleanAll(s.Users)
		out[i] = s
	}
	return out
}
