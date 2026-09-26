// Package ack stores the user's acknowledgements of findings. An
// acknowledgement for a finding about a file is bound to that file's SHA-256:
// if the file changes, the finding comes back.
package ack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/co2water/agentegress/internal/collect"
	"github.com/co2water/agentegress/internal/engine"
)

// Entry is one acknowledgement.
type Entry struct {
	ID         string    `json:"id"`
	Rule       string    `json:"rule"`
	FileSHA256 string    `json:"file_sha256,omitempty"`
	Note       string    `json:"note,omitempty"`
	At         time.Time `json:"at"`
}

// Store is the on-disk list.
type Store struct {
	Path    string  `json:"-"`
	Entries []Entry `json:"entries"`
}

// DefaultPath is $AGENTEGRESS_ACKS, or %APPDATA%\agentegress\acks.json.
func DefaultPath() string {
	if p := os.Getenv("AGENTEGRESS_ACKS"); p != "" {
		return p
	}
	return filepath.Join(os.Getenv("APPDATA"), "agentegress", "acks.json")
}

// errNotLocal refuses a store on a network share (AppData folder redirection,
// or AGENTEGRESS_ACKS pointing at one) or at a relative path: the tool never
// opens files where doing so could connect to another machine (third review,
// item 17).
func errNotLocal(path string) error {
	return fmt.Errorf("acknowledgement store %s is not on a local drive; not opened", path)
}

// Load reads a store; a missing file is an empty store.
func Load(path string) (*Store, error) {
	s := &Store{Path: path}
	if collect.IsRemotePath(path) {
		return nil, errNotLocal(path)
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

// Save writes the store atomically.
func (s *Store) Save() error {
	if collect.IsRemotePath(s.Path) {
		return errNotLocal(s.Path)
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Add acknowledges f, replacing any earlier entry for the same ID.
func (s *Store) Add(f engine.Finding, note string, now time.Time) error {
	e := Entry{ID: f.ID, Rule: f.Rule, Note: note, At: now.UTC()}
	if f.File() != "" {
		h, err := HashFile(f.File())
		if err != nil {
			return errors.New("cannot read the file this finding is about, so the acknowledgement could not be bound to its content: " + err.Error())
		}
		e.FileSHA256 = h
	}
	s.Remove(f.ID)
	s.Entries = append(s.Entries, e)
	return nil
}

// Remove drops the entry for id and reports whether one existed.
func (s *Store) Remove(id string) bool {
	n := len(s.Entries)
	s.Entries = slices.DeleteFunc(s.Entries, func(e Entry) bool { return e.ID == id })
	return len(s.Entries) != n
}

// Apply marks acknowledged findings and re-tallies the report. A file-bound
// entry only applies while the file still hashes to the recorded value.
func (s *Store) Apply(r *engine.Report, hash func(string) (string, error)) {
	byID := map[string]Entry{}
	for _, e := range s.Entries {
		byID[e.ID] = e
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		e, ok := byID[f.ID]
		if !ok {
			continue
		}
		if e.FileSHA256 != "" {
			h, err := hash(f.File())
			if err != nil || h != e.FileSHA256 {
				continue // file changed or vanished: the finding is live again
			}
		}
		f.Acked = true
	}
	r.Tally()
}

// HashFile returns the hex SHA-256 of a file.
func HashFile(path string) (string, error) {
	if collect.IsRemotePath(path) {
		return "", errors.New("file is on a network location; agentegress does not open those")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
