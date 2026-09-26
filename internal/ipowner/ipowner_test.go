package ipowner

import (
	"net/netip"
	"testing"
)

func TestLookup(t *testing.T) {
	cases := map[string]string{
		"160.79.104.10":        "Anthropic",
		"2607:6bc0::10":        "Anthropic",
		"104.16.0.1":           "Cloudflare",
		"192.168.1.1":          "",
		"::ffff:160.79.104.10": "Anthropic",
	}
	for ip, want := range cases {
		if got := Lookup(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", ip, got, want)
		}
	}
	if got := Lookup(netip.MustParseAddr("34.149.66.165")); got != "Google Cloud" && got != "Google" {
		t.Errorf("Lookup(34.149.66.165) = %q, want a Google label", got)
	}
	if Size() < 1000 {
		t.Errorf("only %d prefixes embedded", Size())
	}
}
