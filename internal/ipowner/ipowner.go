// Package ipowner labels IP addresses with the organisation that publishes the
// range they belong to. Data is embedded at build time (see tools/genranges);
// lookups never touch the network. An address outside every known range gets
// no label rather than a guess.
package ipowner

import (
	_ "embed"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

//go:embed ranges.txt
var rangesTxt string

type entry struct {
	p   netip.Prefix
	org string
}

var (
	once  sync.Once
	table []entry // sorted most specific first
)

func load() {
	for _, line := range strings.Split(rangesTxt, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		pfx, org, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		p, err := netip.ParsePrefix(pfx)
		if err != nil {
			continue
		}
		table = append(table, entry{p, org})
	}
	slices.SortStableFunc(table, func(a, b entry) int { return b.p.Bits() - a.p.Bits() })
}

// Lookup returns the organisation for a, or "" when unknown.
func Lookup(a netip.Addr) string {
	once.Do(load)
	a = a.Unmap()
	for _, e := range table {
		if e.p.Contains(a) {
			return e.org
		}
	}
	return ""
}

// Size is the number of embedded prefixes.
func Size() int {
	once.Do(load)
	return len(table)
}
