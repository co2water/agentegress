package snapshot

import (
	"encoding/json"
	"io"
	"slices"
)

// Load reads a snapshot written as JSON (for example by `scan -json` or the
// red-team fixture generator) and rebuilds the child lists, which are not
// serialised.
func Load(r io.Reader) (*Snapshot, error) {
	var s Snapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, err
	}
	if s.Procs == nil {
		s.Procs = map[uint32]*Proc{}
	}
	for pid, p := range s.Procs {
		p.PID = pid
		p.Children = nil
	}
	for pid, p := range s.Procs {
		if parent, ok := s.Procs[p.Parent]; ok && p.Parent != pid {
			parent.Children = append(parent.Children, pid)
		}
	}
	for _, p := range s.Procs {
		slices.Sort(p.Children)
	}
	return &s, nil
}
