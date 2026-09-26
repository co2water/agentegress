// Command democast writes docs/demo.cast, an asciinema v2 recording of
// `agentegress scan` on the synthetic machine in examples/compromised.json.
// Every line shown is real output of that command; nothing is typed by hand.
// Render it with svgcast (https://github.com/co2water/svgcast):
//
//	go build -o bin/agentegress.exe ./cmd/agentegress
//	go run ./tools/democast
//	svgcast docs/demo.cast -o docs/demo.svg
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	green  = "\033[32m"
	blue   = "\033[34m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	grey   = "\033[90m"
	bold   = "\033[1m"
	reset  = "\033[0m"
)

func main() {
	cmdline := "agentegress scan -fixture examples/compromised.json"
	out, err := exec.Command("bin/agentegress.exe", "scan", "-fixture", "examples/compromised.json").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "democast: run the build first:", err)
		os.Exit(1)
	}
	lines := pick(strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n"))

	width := 100
	var ev [][]any
	t := 0.0
	emit := func(dt float64, s string) {
		t += dt
		ev = append(ev, []any{float64(int(t*1000)) / 1000, "o", s})
	}
	prompt := green + "~/demo" + reset + " " + blue + ">" + reset + " "
	emit(0.4, prompt)
	for _, ch := range cmdline {
		emit(0.045, string(ch))
	}
	emit(0.4, "\r\n")
	for i, l := range lines {
		dt := 0.03
		if i == 0 {
			dt = 0.8 // the scan
		}
		if strings.HasPrefix(l, "VERDICT") || strings.HasPrefix(l, "AI AGENTS") {
			dt = 0.5
		}
		emit(dt, colour(l)+"\r\n")
	}
	emit(0.8, prompt)
	emit(2.5, "")

	f, err := os.Create("docs/demo.cast")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	header, _ := json.Marshal(map[string]any{"version": 2, "width": width, "height": len(lines) + 3, "title": "agentegress demo"})
	fmt.Fprintln(f, string(header))
	for _, e := range ev {
		b, _ := json.Marshal(e)
		fmt.Fprintln(f, string(b))
	}
	fmt.Printf("wrote docs/demo.cast (%d lines, %.1fs)\n", len(lines), t)
}

// pick keeps the verdict, finding headlines with their first evidence line,
// and the agent tree; it drops long command lines and the other tables so the
// demo fits one screen.
func pick(all []string) []string {
	var out []string
	section := ""
	for _, l := range all {
		switch {
		case strings.HasPrefix(l, "VERDICT"):
			section = "verdict"
		case strings.HasPrefix(l, "AI AGENTS"):
			section = "agents"
		case strings.HasPrefix(l, "OTHER PROCESSES"), strings.HasPrefix(l, "LISTENING ON"), strings.HasPrefix(l, "MCP SERVERS"):
			section = "skip"
		}
		switch section {
		case "verdict":
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "command_line:") || strings.HasPrefix(t, "process:") || strings.HasPrefix(t, "To accept") ||
				strings.HasPrefix(t, "entry_name:") || strings.HasPrefix(t, "location:") || strings.HasPrefix(t, "command:") {
				continue
			}
			if len(l) > 100 {
				l = l[:99] + "…"
			}
			out = append(out, l)
		case "agents":
			if strings.HasPrefix(strings.TrimSpace(l), "C:\\Program Files\\WindowsApps") {
				continue
			}
			if len(l) > 100 {
				l = l[:99] + "…"
			}
			out = append(out, l)
		}
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}

func colour(l string) string {
	t := strings.TrimSpace(l)
	switch {
	case strings.HasPrefix(l, "VERDICT"):
		return bold + red + l + reset
	case strings.HasPrefix(t, "HIGH") || strings.HasPrefix(t, "CRITICAL"):
		return red + l + reset
	case strings.HasPrefix(t, "MEDIUM") || strings.HasPrefix(t, "LOW"):
		return yellow + l + reset
	case strings.HasPrefix(t, "host text"):
		return grey + l + reset
	case strings.HasPrefix(l, "AI AGENTS"):
		return bold + l + reset
	}
	l = strings.ReplaceAll(l, "✓", green+"✓"+reset)
	l = strings.ReplaceAll(l, "✗", red+"✗"+reset)
	l = strings.ReplaceAll(l, "⚠", yellow+"⚠"+reset)
	if strings.Contains(l, "[Anthropic]") || strings.Contains(l, "[GitHub]") {
		l = strings.Replace(l, "→", cyan+"→"+reset, 1)
	}
	return l
}
