package mcptools

import (
	"github.com/co2water/agentegress/internal/mcp"
	"github.com/co2water/agentegress/internal/snapshot"
)

// NewNaiveServer is the red-team baseline. It exposes the same facts the real
// server does — processes with agent attribution, signatures and payloads,
// peer organisations and DNS names, listeners, autostarts, MCP configs, host
// settings, logons and coverage limits — but raw: no rule verdict or findings,
// no untrusted envelope, no sanitising, no guidance. The difference between
// the two servers is therefore the design, not the amount of data (an
// independent audit found an earlier version gave the baseline less data).
// Never ship it as a user feature.
func NewNaiveServer(src Source, version string) *mcp.Server {
	empty := map[string]any{"type": "object", "properties": map[string]any{}}
	load := func() (*snapshot.Snapshot, error) {
		s, _, err := src()
		return s, err
	}
	return &mcp.Server{
		Name: "agentegress-naive", Version: version,
		Instructions: "Tools to inspect processes, network connections, autostart programs and security settings on this Windows PC.",
		Tools: []mcp.Tool{
			{Name: "get_processes", Description: "Processes started by AI agents or with network activity: command lines, signatures, the file a script host runs, agent and MCP attribution, connections with peer organisation and DNS names, and listening ports.",
				InputSchema: empty, Annotations: mcp.ReadOnly, Handler: func(map[string]any) (any, error) {
					s, err := load()
					if err != nil {
						return nil, err
					}
					var out []map[string]any
					for pid, p := range s.Procs {
						var conns []map[string]any
						for _, c := range s.Conns {
							if c.PID != pid || !(c.External || c.Exposed) {
								continue
							}
							m := map[string]any{"state": c.State, "dns_names": c.Hosts, "peer_org": c.Org}
							if c.Exposed {
								m["listening_on"] = c.Local
							} else {
								m["remote"] = c.Remote
							}
							conns = append(conns, m)
						}
						if p.Root == 0 && len(conns) == 0 {
							continue
						}
						sig, signer := "not_checked", ""
						if !p.Readable {
							sig = "no_access"
						}
						if p.Signature != nil {
							sig, signer = string(p.Signature.Status), p.Signature.Signer
						}
						m := map[string]any{"pid": pid, "parent_pid": p.PPID, "name": p.Name, "path": p.Path,
							"command_line": p.Cmdline, "signature": sig, "signer": signer,
							"in_user_writable_dir": p.UserDir, "agent": string(p.Agent), "under_agent": string(p.Owner),
							"mcp_config_name": p.MCP, "connections": conns}
						if p.Payload != "" {
							ps := "not_checked"
							if p.PayloadSignature != nil {
								ps = string(p.PayloadSignature.Status)
							}
							m["runs_file"], m["runs_file_signature"], m["runs_file_in_user_writable_dir"] = p.Payload, ps, p.PayloadUserDir
						}
						if p.UpdatedTo != "" && p.UpdatedToSignature != nil {
							m["updated_file"], m["updated_file_signature"] = p.UpdatedTo, string(p.UpdatedToSignature.Status)
						}
						out = append(out, m)
					}
					return map[string]any{"processes": out}, nil
				}},
			{Name: "get_autostarts", Description: "Programs configured to start automatically, with signature status.",
				InputSchema: empty, Annotations: mcp.ReadOnly, Handler: func(map[string]any) (any, error) {
					s, err := load()
					if err != nil {
						return nil, err
					}
					var out []map[string]any
					for _, a := range s.Autostarts {
						sig, signer := "not_checked", ""
						if a.Signature != nil {
							sig, signer = string(a.Signature.Status), a.Signature.Signer
						}
						hostSig := ""
						if a.HostSignature != nil {
							hostSig = string(a.HostSignature.Status)
						}
						out = append(out, map[string]any{"kind": a.Kind, "scope": a.Scope, "name": a.Name, "location": a.Location,
							"command": a.Command, "target": a.Target, "host": a.Host, "host_signature": hostSig,
							"signature": sig, "signer": signer, "disabled": a.Disabled, "in_user_writable_dir": a.UserDir})
					}
					return map[string]any{"autostarts": out}, nil
				}},
			{Name: "get_mcp_configs", Description: "MCP servers configured in AI clients.",
				InputSchema: empty, Annotations: mcp.ReadOnly, Handler: func(map[string]any) (any, error) {
					s, err := load()
					if err != nil {
						return nil, err
					}
					return map[string]any{"servers": s.MCPServers}, nil
				}},
			{Name: "get_host_security", Description: "Remote Desktop and firewall settings, recent logons, and what this scan could not check.",
				InputSchema: empty, Annotations: mcp.ReadOnly, Handler: func(map[string]any) (any, error) {
					s, err := load()
					if err != nil {
						return nil, err
					}
					return map[string]any{"host": s.Host, "logons": s.Logons, "not_checked": s.Coverage.Limits}, nil
				}},
		},
	}
}
