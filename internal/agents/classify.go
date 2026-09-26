// Package agents recognises AI agent processes and the tool / MCP processes they spawn.
package agents

import (
	"regexp"
	"strings"
	"unicode"
)

// Kind names an AI agent product. The empty Kind means "not an agent".
type Kind string

const (
	ClaudeCode    Kind = "Claude Code"
	ClaudeDesktop Kind = "Claude Desktop"
	Cursor        Kind = "Cursor"
	VSCode        Kind = "VS Code"
	Windsurf      Kind = "Windsurf"
	Codex         Kind = "Codex"
	GeminiCLI     Kind = "Gemini CLI"
	OpenCode      Kind = "opencode"
	Antigravity   Kind = "Antigravity"
	Kiro          Kind = "Kiro"
	Trae          Kind = "Trae"
	Goose         Kind = "Goose"
	Aider         Kind = "Aider"
	CopilotCLI    Kind = "Copilot CLI"
	Amp           Kind = "Amp"
)

// Classify decides whether a process is an agent, from its image name, path and
// command line. Inputs are untrusted; a lying process can only claim to be an
// agent, which puts it under more scrutiny, not less.
func Classify(name, path, cmdline string) Kind {
	n := strings.ToLower(name)
	p := strings.ToLower(path)
	c := strings.ReplaceAll(strings.ToLower(cmdline), `\`, "/")
	switch n {
	case "claude.exe":
		if strings.Contains(p, `\anthropicclaude\`) || strings.Contains(p, `\windowsapps\`) {
			return ClaudeDesktop
		}
		return ClaudeCode
	case "cursor.exe":
		return Cursor
	case "code.exe":
		return VSCode
	case "windsurf.exe":
		return Windsurf
	case "codex.exe":
		return Codex
	case "opencode.exe":
		return OpenCode
	case "antigravity.exe":
		return Antigravity
	case "kiro.exe":
		return Kiro
	case "trae.exe":
		return Trae
	case "goose.exe":
		return Goose
	case "aider.exe":
		return Aider
	case "python.exe", "pythonw.exe", "python3.exe":
		if strings.Contains(c, "-m aider") || strings.Contains(c, "/aider ") {
			return Aider
		}
	case "node.exe", "bun.exe":
		switch {
		case strings.Contains(c, "@anthropic-ai/claude-code"):
			return ClaudeCode
		case strings.Contains(c, "@openai/codex"):
			return Codex
		case strings.Contains(c, "@google/gemini-cli"):
			return GeminiCLI
		case strings.Contains(c, "@github/copilot"):
			return CopilotCLI
		case strings.Contains(c, "@sourcegraph/amp"):
			return Amp
		}
	}
	return ""
}

var mcpHint = regexp.MustCompile(`(?i)(\bmcp\b|mcp[-_]|[-_/@]mcp|modelcontextprotocol|server-[a-z])`)

// LooksLikeMCP reports whether a child process's command line suggests an MCP server.
func LooksLikeMCP(cmdline string) bool { return mcpHint.MatchString(cmdline) }

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)((?:token|api[-_]?key|secret|password|passwd|pwd|auth)[=:\s]+)("[^"]*"|\S+)`),
	regexp.MustCompile(`\b(sk-[A-Za-z0-9_-]{8})[A-Za-z0-9_-]+`),
	regexp.MustCompile(`\b(gh[pousr]_)[A-Za-z0-9]{8,}`),
	regexp.MustCompile(`\b(github_pat_)[A-Za-z0-9_]{8,}`),
	regexp.MustCompile(`(://[^/\s:@]+:)[^@\s]+@`),
}

// Redact masks credential-looking values before text leaves the engine.
func Redact(s string) string {
	s = secretPatterns[0].ReplaceAllString(s, "${1}***")
	s = secretPatterns[1].ReplaceAllString(s, "${1}***")
	s = secretPatterns[2].ReplaceAllString(s, "${1}***")
	s = secretPatterns[3].ReplaceAllString(s, "${1}***")
	s = secretPatterns[4].ReplaceAllString(s, "${1}***@")
	return s
}

// Invisible reports characters that render as nothing but can still steer a
// model or split a keyword: every Unicode format character (zero-width space
// and joiners, BOM, soft hyphen, bidi controls and marks, tag characters),
// variation selectors, and the Hangul/Mongolian fillers that display blank.
func Invisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) ||
		(r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) ||
		(r >= 0x180B && r <= 0x180F) || // Mongolian variation selectors and vowel separator
		r == 0x034F || // combining grapheme joiner
		r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0
}

// confusables maps letters that look like ASCII to the ASCII letter, for
// matching only (never for display): Cyrillic and Greek look-alikes, and the
// full-width forms.
var confusables = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd',
	'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g', 'ո': 'n', 'ս': 'u', 'ｍ': 'm',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
	'Ѕ': 'S', 'І': 'I', 'Ј': 'J', 'Ү': 'Y',
	'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'ι': 'i', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
	'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X', 'Ζ': 'Z',
}

// letterlike holds the Letterlike Symbols that fill the gaps in the
// mathematical alphabets (script h is U+210E, not in the math block).
var letterlike = map[rune]rune{
	'ℂ': 'C', 'ℊ': 'g', 'ℋ': 'H', 'ℌ': 'H', 'ℍ': 'H', 'ℎ': 'h', 'ℐ': 'I', 'ℑ': 'I', 'ℒ': 'L', 'ℕ': 'N',
	'ℙ': 'P', 'ℚ': 'Q', 'ℛ': 'R', 'ℜ': 'R', 'ℝ': 'R', 'ℤ': 'Z', 'ℨ': 'Z', 'ℬ': 'B', 'ℭ': 'C', 'ℯ': 'e',
	'ℰ': 'E', 'ℱ': 'F', 'ℳ': 'M', 'ℴ': 'o', 'ı': 'i', 'ȷ': 'j',
}

// Skeleton folds look-alike letters and full-width ASCII to plain ASCII so
// that "іgnоrе" (with Cyrillic letters) matches "ignore". It also folds the
// mathematical alphanumeric styles (bold, italic, script, monospace, ...),
// dotless i, and drops combining marks ("i" + U+0307 reads as "i") — third
// review, item 15. For matching only.
func Skeleton(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0xFF01 && r <= 0xFF5E:
			return r - 0xFF01 + '!'
		case r >= 0x1D400 && r <= 0x1D6A3: // 13 styles of A–Z a–z
			off := (r - 0x1D400) % 52
			if off < 26 {
				return 'A' + off
			}
			return 'a' + off - 26
		case r >= 0x1D7CE && r <= 0x1D7FF: // 5 styles of 0–9
			return '0' + (r-0x1D7CE)%10
		case unicode.Is(unicode.Mn, r):
			return -1
		}
		if a, ok := confusables[r]; ok {
			return a
		}
		if a, ok := letterlike[r]; ok {
			return a
		}
		return r
	}, s)
}

// StripInvisible removes Invisible characters only.
func StripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if Invisible(r) {
			return -1
		}
		return r
	}, s)
}

// Sanitize strips control, bidi and Unicode tag characters and truncates, so
// host text cannot smuggle hidden instructions or break terminal/LLM framing.
func Sanitize(s string, limit int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Cc, r) || r == 0x2028 || r == 0x2029:
			b.WriteRune(' ') // C0/C1 controls (incl. ESC and 8-bit CSI), line/paragraph separators
		case Invisible(r):
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if limit > 0 && len([]rune(out)) > limit {
		out = string([]rune(out)[:limit]) + "…"
	}
	return out
}
