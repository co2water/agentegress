//go:build !windows

package snapshot

import "errors"

// Gather scans the live machine, which is only possible on Windows. On other
// systems the binary still serves saved snapshots (scan -fixture, mcp
// -fixture), which is how MCP directories inspect the tool definitions.
func Gather() (*Snapshot, error) {
	return nil, errors.New("live scanning is only supported on Windows; use -fixture with a saved snapshot")
}
