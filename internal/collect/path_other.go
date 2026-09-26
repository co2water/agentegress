//go:build !windows

package collect

import "strings"

// IsRemotePath on non-Windows builds (used only by tests and tools there)
// treats UNC-style paths as remote.
func IsRemotePath(path string) bool {
	p := strings.TrimSpace(path)
	return len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/')
}

func canonicalPath(path string) (string, bool) {
	if IsRemotePath(path) || strings.Contains(path, "~") {
		return "", false
	}
	return strings.ToLower(path), true
}
