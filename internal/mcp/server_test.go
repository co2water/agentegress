package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func run(t *testing.T, s *Server, lines ...string) []map[string]any {
	t.Helper()
	var out strings.Builder
	if err := s.Serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var res []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("bad json %q: %v", l, err)
		}
		res = append(res, m)
	}
	return res
}

func testServer() *Server {
	return &Server{Name: "t", Version: "1", Instructions: "be careful", Preamble: "PRE", Tools: []Tool{
		{Name: "echo", Description: "d", InputSchema: map[string]any{"type": "object"}, Annotations: ReadOnly,
			Handler: func(a map[string]any) (any, error) { return map[string]any{"got": a["x"]}, nil }},
		{Name: "fail", Description: "d", InputSchema: map[string]any{"type": "object"},
			Handler: func(map[string]any) (any, error) { return nil, errors.New("nope") }},
		{Name: "panic", Description: "d", InputSchema: map[string]any{"type": "object"},
			Handler: func(map[string]any) (any, error) { panic("boom") }},
	}}
}

func TestLifecycle(t *testing.T) {
	res := run(t, testServer(),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"x":"hi"}}}`,
		`{"jsonrpc":"2.0","id":"s4","method":"ping"}`,
	)
	if len(res) != 4 { // the notification gets no reply
		t.Fatalf("got %d replies: %v", len(res), res)
	}
	init := res[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" || init["instructions"] != "be careful" {
		t.Errorf("initialize = %v", init)
	}
	tools := res[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 3 || tools[0].(map[string]any)["annotations"].(map[string]any)["readOnlyHint"] != true {
		t.Errorf("tools = %v", tools)
	}
	call := res[2]["result"].(map[string]any)
	text := call["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.HasPrefix(text, "PRE\n\n{") || !strings.Contains(text, `"got": "hi"`) {
		t.Errorf("text = %q", text)
	}
	if call["structuredContent"].(map[string]any)["got"] != "hi" {
		t.Errorf("structured = %v", call["structuredContent"])
	}
	if res[3]["id"] != "s4" {
		t.Errorf("string id not echoed: %v", res[3])
	}
}

func TestVersionNegotiation(t *testing.T) {
	for req, want := range map[string]string{"2024-11-05": "2024-11-05", "2099-01-01": Versions[0], "": Versions[0]} {
		res := run(t, testServer(), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+req+`"}}`)
		if got := res[0]["result"].(map[string]any)["protocolVersion"]; got != want {
			t.Errorf("requested %q got %v want %s", req, got, want)
		}
	}
	// Old protocol: no structuredContent.
	res := run(t, testServer(),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}`)
	if _, ok := res[1]["result"].(map[string]any)["structuredContent"]; ok {
		t.Error("structuredContent sent to a 2024-11-05 client")
	}
}

// Review finding #11: one oversized line used to end the whole session.
func TestOversizedLineKeepsServing(t *testing.T) {
	old := MaxLine
	MaxLine = 1024
	defer func() { MaxLine = old }()
	res := run(t, testServer(),
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"`+strings.Repeat("x", 5000)+`"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if len(res) != 2 || res[0]["error"] == nil || res[1]["id"] != float64(2) {
		t.Fatalf("replies = %v", res)
	}
}

func TestErrors(t *testing.T) {
	res := run(t, testServer(),
		`not json`,
		`{"jsonrpc":"2.0","id":1,"method":"nope"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"missing"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fail"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"panic"}}`,
		`[{"jsonrpc":"2.0","id":5,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/x"}]`,
	)
	codes := []float64{codeParse, codeMethodNotFound, codeInvalidParams}
	for i, c := range codes {
		if e, ok := res[i]["error"].(map[string]any); !ok || e["code"] != c {
			t.Errorf("reply %d = %v, want error %v", i, res[i], c)
		}
	}
	for _, i := range []int{3, 4} {
		r := res[i]["result"].(map[string]any)
		if r["isError"] != true {
			t.Errorf("reply %d should be a tool error: %v", i, r)
		}
	}
	if len(res) != 6 || res[5]["id"] != float64(5) {
		t.Errorf("batch reply = %v", res[len(res)-1])
	}
}
