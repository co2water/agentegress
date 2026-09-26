package collect

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Autostart is one thing Windows launches without the user asking: a Run key
// value, a startup-folder item, a scheduled task, a service or a Winlogon value.
type Autostart struct {
	Kind     string `json:"kind"`  // run-key, startup-folder, scheduled-task, service, winlogon
	Scope    string `json:"scope"` // user or machine
	Location string `json:"location"`
	Name     string `json:"name"`
	Command  string `json:"command"`
	Target   string `json:"target,omitempty"` // resolved executable, or the file a script host loads
	Host     string `json:"host,omitempty"`   // script host (rundll32, wscript, ...) when Target is its payload
	Disabled bool   `json:"disabled,omitempty"`
}

// Resolve fills Target and Host from Command.
func (a Autostart) Resolve() Autostart {
	a.Target, a.Host = ResolveTarget(a.Command)
	return a
}

// HostConfig holds remote-access and firewall settings.
type HostConfig struct {
	RDPEnabled       bool     `json:"rdp_enabled"`
	RDPKnown         bool     `json:"rdp_known"`
	FirewallDisabled []string `json:"firewall_disabled_profiles,omitempty"`
	FirewallKnown    bool     `json:"firewall_known"`
}

// LogonSource aggregates logon events from one source address.
type LogonSource struct {
	IP    string   `json:"ip"`
	Count int      `json:"count"`
	Users []string `json:"users,omitempty"` // at most 5
}

// Logons summarises Security-log logon activity.
type Logons struct {
	Checked    bool          `json:"checked"`
	Reason     string        `json:"reason,omitempty"` // why not checked
	Hours      int           `json:"hours"`
	Failed     []LogonSource `json:"failed,omitempty"`      // event 4625
	RemoteDesk []LogonSource `json:"rdp_success,omitempty"` // event 4624, logon type 10
	Truncated  bool          `json:"truncated,omitempty"`
}

// ParseTasksXML reads `schtasks /query /xml ONE` output: a <Tasks> document
// where each <Task> is preceded by a comment holding its path.
//
// Each task is cut out and decoded on its own, so one task that breaks the
// document (a name containing "--" makes its comment invalid XML) cannot hide
// every other task (third review, item 7). The error, if any, counts the
// tasks that could not be read; the rest are returned.
func ParseTasksXML(b []byte) ([]Autostart, error) {
	var out []Autostart
	failed := 0
	rest := b
	for {
		start := taskStart(rest)
		if start < 0 {
			break
		}
		end := bytes.Index(rest[start:], []byte("</Task>"))
		if end < 0 {
			failed++
			break
		}
		end += start + len("</Task>")
		name := taskComment(rest[:start])
		items, err := parseTask(rest[start:end], name)
		if err != nil {
			failed++
		}
		out = append(out, items...)
		rest = rest[end:]
	}
	if failed > 0 {
		return out, fmt.Errorf("%d scheduled task(s) could not be read", failed)
	}
	return out, nil
}

// taskStart finds the next "<Task" element (not "<Tasks").
func taskStart(b []byte) int {
	off := 0
	for {
		i := bytes.Index(b[off:], []byte("<Task"))
		if i < 0 {
			return -1
		}
		i += off
		if j := i + len("<Task"); j < len(b) && (b[j] == ' ' || b[j] == '>' || b[j] == '\r' || b[j] == '\n' || b[j] == '\t') {
			return i
		}
		off = i + 1
	}
}

// taskComment returns the text of the last comment before a task: its path.
// Task names cannot contain '>', so the last "-->" ends the comment even when
// the name contains "--".
func taskComment(before []byte) string {
	end := bytes.LastIndex(before, []byte("-->"))
	if end < 0 {
		return ""
	}
	start := bytes.LastIndex(before[:end], []byte("<!--"))
	if start < 0 {
		return ""
	}
	return strings.TrimSpace(string(before[start+len("<!--") : end]))
}

func parseTask(b []byte, name string) ([]Autostart, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	var task struct {
		Settings struct {
			Enabled string `xml:"Enabled"`
		} `xml:"Settings"`
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Actions>Exec"`
	}
	if err := dec.Decode(&task); err != nil {
		return nil, err
	}
	var out []Autostart
	for _, e := range task.Exec {
		cmd := strings.TrimSpace(e.Command)
		full := cmd
		if e.Arguments != "" {
			full += " " + strings.TrimSpace(e.Arguments)
		}
		target := ExecutablePath(cmd)
		if target == "" {
			target = ExpandEnv(strings.Trim(cmd, `"`))
		}
		target = ResolveBare(target)
		host := ""
		if pl := Payload(full, target); pl != "" {
			target, host = pl, target
		}
		out = append(out, Autostart{
			Kind: "scheduled-task", Scope: "machine", Location: name, Name: name,
			Command: full, Target: target, Host: host,
			Disabled: strings.EqualFold(strings.TrimSpace(task.Settings.Enabled), "false"),
		})
	}
	return out, nil
}

// LogonEvent is the part of a 4624/4625 event the checks need.
type LogonEvent struct {
	ID        int
	Time      time.Time
	User      string
	IP        string
	LogonType int
}

// ParseLogonEventXML decodes one rendered Security event.
func ParseLogonEventXML(b []byte) (LogonEvent, error) {
	var ev struct {
		System struct {
			EventID     int `xml:"EventID"`
			TimeCreated struct {
				SystemTime string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
		} `xml:"System"`
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"EventData>Data"`
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := dec.Decode(&ev); err != nil {
		return LogonEvent{}, err
	}
	out := LogonEvent{ID: ev.System.EventID}
	out.Time, _ = time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime)
	for _, d := range ev.Data {
		v := strings.TrimSpace(d.Value)
		switch d.Name {
		case "TargetUserName":
			out.User = v
		case "IpAddress":
			if v != "-" {
				out.IP = v
			}
		case "LogonType":
			for _, c := range v {
				if c >= '0' && c <= '9' {
					out.LogonType = out.LogonType*10 + int(c-'0')
				}
			}
		}
	}
	return out, nil
}

// SummariseLogons groups failed logons and successful RDP logons by source.
func SummariseLogons(events []LogonEvent, hours int) Logons {
	failed := map[string]*LogonSource{}
	rdp := map[string]*LogonSource{}
	add := func(m map[string]*LogonSource, e LogonEvent) {
		ip := e.IP
		if ip == "" {
			ip = "local"
		}
		s := m[ip]
		if s == nil {
			s = &LogonSource{IP: ip}
			m[ip] = s
		}
		s.Count++
		if e.User != "" && len(s.Users) < 5 && !slices.Contains(s.Users, e.User) {
			s.Users = append(s.Users, e.User)
		}
	}
	for _, e := range events {
		switch {
		case e.ID == 4625:
			add(failed, e)
		case e.ID == 4624 && e.LogonType == 10:
			add(rdp, e)
		}
	}
	flatten := func(m map[string]*LogonSource) []LogonSource {
		var out []LogonSource
		for _, s := range m {
			out = append(out, *s)
		}
		slices.SortFunc(out, func(a, b LogonSource) int {
			if a.Count != b.Count {
				return b.Count - a.Count
			}
			return strings.Compare(a.IP, b.IP)
		})
		return out
	}
	return Logons{Checked: true, Hours: hours, Failed: flatten(failed), RemoteDesk: flatten(rdp)}
}

// IsPublicIP reports whether s parses as a globally routable address.
func IsPublicIP(s string) bool {
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate()
}
