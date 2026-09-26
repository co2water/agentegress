// Package mcp is a minimal Model Context Protocol server over stdio: newline-
// delimited JSON-RPC 2.0 with initialize, ping, tools/list and tools/call.
// It is hand-written so the binary keeps zero third-party dependencies.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
)

// Versions this server speaks, newest first. Only the tools subset is used,
// which is stable across all of them.
var Versions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// Tool is one callable tool.
type Tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
	// Handler returns a JSON-serialisable result object, or an error that is
	// reported to the model as a tool error (isError), not a protocol error.
	Handler func(args map[string]any) (any, error) `json:"-"`
}

// ReadOnly is the annotation set every agentegress tool carries.
var ReadOnly = map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}

// Server holds the tool registry and session state.
type Server struct {
	Name, Version string
	Instructions  string
	// Preamble is prepended to every text result, ahead of the JSON.
	Preamble string
	Tools    []Tool

	mu       sync.Mutex
	protocol string
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// Serve reads requests from r and writes responses to w until r ends.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	in := bufio.NewReaderSize(r, 64*1024)
	out := bufio.NewWriter(w)
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for {
		raw, tooLong, err := readLine(in, MaxLine)
		if err != nil && len(raw) == 0 && !tooLong {
			if err == io.EOF {
				return nil
			}
			return err
		}
		var replies []response
		line := strings.TrimSpace(string(raw))
		switch {
		case tooLong:
			// One oversized message must not end the session.
			replies = append(replies, errResp(nil, codeParse, "message too large"))
		case line == "":
		case strings.HasPrefix(line, "["): // JSON-RPC batch (2025-03-26)
			var batch []json.RawMessage
			if err := json.Unmarshal([]byte(line), &batch); err != nil {
				replies = append(replies, errResp(nil, codeParse, "parse error"))
			}
			for _, raw := range batch {
				if rp, ok := s.handle(raw); ok {
					replies = append(replies, rp)
				}
			}
		default:
			if rp, ok := s.handle([]byte(line)); ok {
				replies = append(replies, rp)
			}
		}
		for _, rp := range replies {
			if err := enc.Encode(rp); err != nil {
				return err
			}
		}
		if err := out.Flush(); err != nil {
			return err
		}
		if err == io.EOF {
			return nil
		}
	}
}

// MaxLine bounds one JSON-RPC message.
var MaxLine = 16 * 1024 * 1024

// readLine returns the next newline-terminated line. A line longer than max
// is consumed and discarded, and tooLong is set, so the caller can reply with
// an error and keep serving.
func readLine(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, isPrefix, e := r.ReadLine()
		if !tooLong {
			if len(line)+len(chunk) > max {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if e != nil {
			return line, tooLong, e
		}
		if !isPrefix {
			return line, tooLong, nil
		}
	}
}

func errResp(id json.RawMessage, code int, msg string) response {
	if id == nil {
		id = json.RawMessage("null")
	}
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// handle processes one message; ok is false for notifications.
func (s *Server) handle(raw []byte) (response, bool) {
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return errResp(nil, codeParse, "parse error"), true
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		if req.ID == nil {
			return response{}, false
		}
		return errResp(req.ID, codeInvalidRequest, "invalid request"), true
	}
	if req.ID == nil { // notification: notifications/initialized, cancelled, ...
		return response{}, false
	}
	result, rerr := s.dispatch(req)
	if rerr != nil {
		return response{JSONRPC: "2.0", ID: req.ID, Error: rerr}, true
	}
	return response{JSONRPC: "2.0", ID: req.ID, Result: result}, true
}

func (s *Server) dispatch(req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		v := Versions[0]
		if slices.Contains(Versions, p.ProtocolVersion) {
			v = p.ProtocolVersion
		}
		s.mu.Lock()
		s.protocol = v
		s.mu.Unlock()
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
			"instructions":    s.Instructions,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": s.Tools}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{codeInvalidParams, "invalid params"}
		}
		i := slices.IndexFunc(s.Tools, func(t Tool) bool { return t.Name == p.Name })
		if i < 0 {
			return nil, &rpcError{codeInvalidParams, "unknown tool: " + p.Name}
		}
		if p.Arguments == nil {
			p.Arguments = map[string]any{}
		}
		return s.call(s.Tools[i], p.Arguments), nil
	}
	return nil, &rpcError{codeMethodNotFound, "method not found: " + req.Method}
}

func (s *Server) call(t Tool, args map[string]any) map[string]any {
	res, err := safeCall(t.Handler, args)
	if err != nil {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}}, "isError": true}
	}
	body, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}}, "isError": true}
	}
	text := string(body)
	if s.Preamble != "" {
		text = s.Preamble + "\n\n" + text
	}
	out := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
	s.mu.Lock()
	structured := s.protocol >= "2025-06-18"
	s.mu.Unlock()
	if structured {
		out["structuredContent"] = res
	}
	return out
}

func safeCall(h func(map[string]any) (any, error), args map[string]any) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v", r)
		}
	}()
	return h(args)
}
