//go:build windows

// Command agentegress shows which AI agent, and which of its MCP servers, is
// talking to what, and checks the host for signs of compromise. Read-only; it
// never opens a network connection of its own.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/co2water/agentegress/internal/ack"
	"github.com/co2water/agentegress/internal/engine"
	"github.com/co2water/agentegress/internal/mcptools"
	"github.com/co2water/agentegress/internal/render"
	"github.com/co2water/agentegress/internal/snapshot"
)

const version = "0.0.3-w3"

const usage = `agentegress — see what your AI agents and their MCP servers connect to,
and check this PC for signs of compromise.

Usage:
  agentegress [scan] [-json] [-v]       scan this machine (default)
  agentegress ack <id> [-note "why"]    accept a finding you have checked
  agentegress unack <id>                undo an acknowledgement
  agentegress mcp                       run as an MCP server on stdio (read-only tools)
  agentegress version

Flags for scan:
  -json            print the report and the full model as JSON (known credential formats redacted)
  -v               show every process in agent trees and details of info findings
  -fixture <file>  report on a saved snapshot instead of this PC (demos, bug reports)

Acknowledgements live in %APPDATA%\agentegress\acks.json. One that is about a
file is tied to the file's SHA-256: if the file changes, the finding returns.
`

func main() {
	args := os.Args[1:]
	cmd := "scan"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "scan":
		scan(args)
	case "ack":
		ackCmd(args)
	case "unack":
		unackCmd(args)
	case "mcp":
		mcpCmd(args)
	case "version":
		fmt.Println("agentegress", version)
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

// evaluate gathers, runs the rules and applies acknowledgements.
func evaluate() (*snapshot.Snapshot, engine.Report, *ack.Store, error) {
	s, err := snapshot.Gather()
	if err != nil {
		return nil, engine.Report{}, nil, err
	}
	rep := engine.Evaluate(s)
	store, err := ack.Load(ack.DefaultPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentegress: ignoring unreadable acknowledgements:", err)
		store = &ack.Store{Path: ack.DefaultPath()}
	}
	store.Apply(&rep, ack.HashFile)
	return s, rep, store, nil
}

func scan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	asJSON := fs.Bool("json", false, "")
	verbose := fs.Bool("v", false, "")
	fixture := fs.String("fixture", "", "")
	fs.Parse(args)

	var (
		s   *snapshot.Snapshot
		rep engine.Report
		err error
	)
	if *fixture != "" {
		// Render a saved snapshot (demos, docs, bug reports) instead of this PC.
		f, ferr := os.Open(*fixture)
		if ferr != nil {
			fatal(ferr)
		}
		s, err = snapshot.Load(f)
		f.Close()
		if err == nil {
			rep = engine.Evaluate(s)
		}
	} else {
		s, rep, _, err = evaluate()
	}
	if err != nil {
		fatal(err)
	}
	if *asJSON {
		out := struct {
			Version  string             `json:"version"`
			Report   engine.Report      `json:"report"`
			Snapshot *snapshot.Snapshot `json:"snapshot"`
		}{version, rep, snapshot.Redacted(s)}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fatal(err)
		}
		return
	}
	render.Text(os.Stdout, s, &rep, render.Options{Verbose: *verbose})
}

func ackCmd(args []string) {
	fs := flag.NewFlagSet("ack", flag.ExitOnError)
	note := fs.String("note", "", "")
	id, rest := splitID(args)
	fs.Parse(rest)
	if id == "" {
		id = fs.Arg(0)
	}
	if id == "" {
		fatal(fmt.Errorf("usage: agentegress ack <id> [-note \"why\"]"))
	}
	_, rep, store, err := evaluate()
	if err != nil {
		fatal(err)
	}
	for _, f := range rep.Findings {
		if f.ID != id {
			continue
		}
		if err := store.Add(f, *note, time.Now()); err != nil {
			fatal(err)
		}
		if err := store.Save(); err != nil {
			fatal(err)
		}
		fmt.Printf("Acknowledged %s: %s\n", f.ID, f.Title)
		if f.File() != "" {
			fmt.Println("Tied to the current content of the file; it will be reported again if the file changes.")
		}
		return
	}
	fatal(fmt.Errorf("no current finding has id %q (run a scan to see ids)", id))
}

func unackCmd(args []string) {
	id, _ := splitID(args)
	if id == "" {
		fatal(fmt.Errorf("usage: agentegress unack <id>"))
	}
	store, err := ack.Load(ack.DefaultPath())
	if err != nil {
		fatal(err)
	}
	if !store.Remove(id) {
		fatal(fmt.Errorf("%q is not acknowledged", id))
	}
	if err := store.Save(); err != nil {
		fatal(err)
	}
	fmt.Println("Removed acknowledgement", id)
}

// mcpCmd serves the read-only tools over stdio. Scans are cached briefly so a
// model calling several tools in one turn sees one consistent snapshot.
// -fixture serves a saved snapshot instead of scanning (red-team suite).
func mcpCmd(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	fixture := fs.String("fixture", "", "")
	ttl := fs.Duration("cache", 15*time.Second, "")
	naive := fs.Bool("naive-baseline", false, "") // red-team comparison only; requires -fixture
	fs.Parse(args)
	if *naive && *fixture == "" {
		fatal(fmt.Errorf("-naive-baseline is a red-team comparison mode and only runs with -fixture"))
	}

	var (
		mu   sync.Mutex
		s    *snapshot.Snapshot
		rep  engine.Report
		when time.Time
	)
	src := func() (*snapshot.Snapshot, engine.Report, error) {
		mu.Lock()
		defer mu.Unlock()
		if *fixture != "" {
			if s == nil {
				f, err := os.Open(*fixture)
				if err != nil {
					return nil, rep, err
				}
				defer f.Close()
				if s, err = snapshot.Load(f); err != nil {
					return nil, rep, err
				}
				rep = engine.Evaluate(s)
			}
			return s, rep, nil
		}
		if s == nil || time.Since(when) > *ttl {
			ns, nrep, _, err := evaluate()
			if err != nil {
				return nil, rep, err
			}
			s, rep, when = ns, nrep, time.Now()
		}
		return s, rep, nil
	}
	srv := mcptools.NewServer(src, version)
	if *naive {
		srv = mcptools.NewNaiveServer(src, version)
	}
	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "agentegress mcp:", err)
		os.Exit(1)
	}
}

// splitID lets the id come before flags ("ack H4-1a2b -note x").
func splitID(args []string) (string, []string) {
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		return args[0], args[1:]
	}
	return "", args
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "agentegress:", err)
	os.Exit(1)
}
