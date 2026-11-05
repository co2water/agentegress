package main

import (
	"slices"
	"testing"
)

// Winget review (2026-11-04): "--version" printed usage and "flag provided
// but not defined" instead of the version.
func TestCommandVersionFlags(t *testing.T) {
	for _, c := range []struct {
		in   []string
		cmd  string
		rest []string
	}{
		{nil, "scan", nil},
		{[]string{"version"}, "version", []string{}},
		{[]string{"-version"}, "version", []string{}},
		{[]string{"--version"}, "version", []string{}},
		{[]string{"-json", "-v"}, "scan", []string{"-json", "-v"}},
		{[]string{"ack", "H4-0000"}, "ack", []string{"H4-0000"}},
	} {
		cmd, rest := command(c.in)
		if cmd != c.cmd || !slices.Equal(rest, c.rest) {
			t.Errorf("command(%q) = %q %q, want %q %q", c.in, cmd, rest, c.cmd, c.rest)
		}
	}
}
