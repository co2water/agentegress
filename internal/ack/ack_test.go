package ack

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/co2water/agentegress/internal/collect"
	"github.com/co2water/agentegress/internal/engine"
	"github.com/co2water/agentegress/internal/snapshot"
)

func TestAckBindsToFileContent(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "helper.exe")
	if err := os.WriteFile(bin, []byte("version 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := &snapshot.Snapshot{Procs: map[uint32]*snapshot.Proc{}, Autostarts: []snapshot.Autostart{{
		Autostart: collect.Autostart{Kind: "startup-folder", Scope: "user", Name: "helper.lnk", Target: bin},
		Signature: &collect.Signature{Status: collect.SigUnsigned}, UserDir: true,
	}}}
	rep := engine.Evaluate(snap)
	if rep.Verdict != engine.VerdictAlert || len(rep.Findings) != 1 {
		t.Fatalf("setup: %v %+v", rep.Verdict, rep.Findings)
	}

	store := &Store{Path: filepath.Join(dir, "acks.json")}
	if err := store.Add(rep.Findings[0], "vendor helper, checked by hand", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	store, err := Load(store.Path)
	if err != nil || len(store.Entries) != 1 || store.Entries[0].FileSHA256 == "" {
		t.Fatalf("reload: %v %+v", err, store)
	}

	rep = engine.Evaluate(snap)
	store.Apply(&rep, HashFile)
	if rep.Verdict != engine.VerdictOK || !rep.Findings[0].Acked || rep.Counts["acknowledged"] != 1 {
		t.Fatalf("after ack: %v %+v %v", rep.Verdict, rep.Findings, rep.Counts)
	}

	// Replace the file: the acknowledgement must stop applying.
	if err := os.WriteFile(bin, []byte("version 2, now malicious"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep = engine.Evaluate(snap)
	store.Apply(&rep, HashFile)
	if rep.Verdict != engine.VerdictAlert || rep.Findings[0].Acked {
		t.Fatalf("changed file still acknowledged: %v %+v", rep.Verdict, rep.Findings)
	}

	if !store.Remove(rep.Findings[0].ID) || store.Remove("nope") {
		t.Error("remove")
	}
}

func TestAckWithoutFile(t *testing.T) {
	snap := &snapshot.Snapshot{Procs: map[uint32]*snapshot.Proc{}, Host: collect.HostConfig{FirewallDisabled: []string{"Public"}}}
	rep := engine.Evaluate(snap)
	store := &Store{}
	if err := store.Add(rep.Findings[0], "", time.Now()); err != nil {
		t.Fatal(err)
	}
	rep = engine.Evaluate(snap)
	store.Apply(&rep, HashFile)
	if !rep.Findings[0].Acked || rep.Verdict != engine.VerdictOK {
		t.Fatalf("%+v", rep)
	}
}

func TestLoadMissing(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if err != nil || len(s.Entries) != 0 {
		t.Fatalf("%v %+v", err, s)
	}
}

// Third review, item 17: a store on a share or at a relative path is refused.
func TestStoreNotLocal(t *testing.T) {
	for _, p := range []string{`\\server\share\acks.json`, `\\?\UNC\server\share\acks.json`, `acks.json`} {
		if _, err := Load(p); err == nil {
			t.Errorf("Load(%q) opened a non-local store", p)
		}
		if err := (&Store{Path: p}).Save(); err == nil {
			t.Errorf("Save(%q) wrote a non-local store", p)
		}
	}
}
