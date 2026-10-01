// Package scan is the core of sAIfety: it turns a Document into a Verdict by
// running normalization, iterative decoding and a set of detectors. Nothing in
// this package executes commands or touches the network; analysis is static.
package scan

import "strings"

// Level is the threat level of a finding or a whole document.
// The numeric value doubles as the process exit code of `saifety scan`.
type Level int

const (
	LevelNone     Level = iota // nothing found
	LevelBase                  // базовый: warn the agent, wrap the data
	LevelMedium                // средний: strip instructions before passing on
	LevelCritical              // критичный: block the source
)

func (l Level) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelBase:
		return "base"
	case LevelMedium:
		return "medium"
	case LevelCritical:
		return "critical"
	}
	return "unknown"
}

// ParseLevel is the inverse of Level.String.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(s) {
	case "none":
		return LevelNone, true
	case "base":
		return LevelBase, true
	case "medium":
		return LevelMedium, true
	case "critical":
		return LevelCritical, true
	}
	return LevelNone, false
}

// Action is what the caller must do with the data after analysis.
type Action int

const (
	ActionPass     Action = iota // pass through unchanged
	ActionWarn                   // escape and wrap in a warning block
	ActionSanitize               // remove findings, then pass on
	ActionBlock                  // do not pass the data; block the source
)

func (a Action) String() string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionWarn:
		return "warn"
	case ActionSanitize:
		return "sanitize"
	case ActionBlock:
		return "block"
	}
	return "unknown"
}

// Category names the kind of threat. The list mirrors the "Понятие угрозы"
// table in README.md; impact levels for each live in scan/rules.
type Category string

const (
	CatInstructionOverride Category = "instruction_override" // "ignore previous instructions", role swaps
	CatSystemPrompt        Category = "system_prompt"        // fake system / assistant / tool messages
	CatExfiltration        Category = "exfiltration"         // sending user data outside
	CatDeletion            Category = "deletion"             // destructive file operations
	CatEncryption          Category = "encryption"           // encrypting data on the device
	CatSensitiveOutput     Category = "sensitive_output"     // printing keys, tokens, credentials
	CatInstall             Category = "install"              // installing components
	CatRepoChange          Category = "repo_change"          // adding/replacing package repositories
	CatGPGKey              Category = "gpg_key"              // importing signing keys
	CatCertificate         Category = "certificate"          // installing CA certificates
	CatArbitraryCommand    Category = "arbitrary_command"    // executable command of unclear intent
	CatRemoteExec          Category = "remote_exec"          // running code fetched from the network (curl | sh)
	CatEncodedPayload      Category = "encoded_payload"      // base64/hex/... blobs that decode to text
	CatHiddenText          Category = "hidden_text"          // zero-width, bidi, invisible content
	CatHookConfig          Category = "hook_config"          // agent config that runs commands (settings hooks)
	CatAbortBait           Category = "abort_bait"           // content meant to make a reviewing agent stop scanning
	CatSecret              Category = "secret_material"      // exposed key/token/credential (masked, not blocked)
	CatPII                 Category = "pii"                  // personal data to anonymize (masked, not blocked)
	CatObfuscation         Category = "obfuscation"          // text deliberately scrambled to evade detection
)

// Kind tells the scanner where a document came from; some detectors weigh
// instruction-like text differently for instruction files vs tool results.
type Kind string

const (
	KindFile            Kind = "file"             // arbitrary repository file
	KindInstructions    Kind = "instructions"     // CLAUDE.md, AGENTS.md, .cursorrules, rules
	KindAgentConfig     Kind = "agent_config"     // .claude/settings*.json, .mcp.json
	KindToolResult      Kind = "tool_result"      // MCP tools/call result or built-in tool output
	KindToolDescription Kind = "tool_description" // MCP tool name/description/schema
	KindImage           Kind = "image"            // text extracted from image metadata / OCR
	KindAggregate       Kind = "aggregate"        // repo-level view built from several files
)

// Document is one unit of analysis.
type Document struct {
	Source string // file path, tool name, server name
	Kind   Kind
	Raw    string // as received
	Text   string // normalized (set by Scanner)
	// Trusted marks a source the user declared trusted; the policy lowers the
	// resulting level by one step. Data from a trusted source is still scanned.
	Trusted bool
}

// Span is a byte range in Document.Text (or in a decoded layer).
type Span struct {
	Start, End int
}

// Finding is one detected threat.
type Finding struct {
	Category   Category `json:"category"`
	Level      Level    `json:"level"`      // impact level from the rules table
	Confidence float64  `json:"confidence"` // 0..1, detector's certainty
	Detector   string   `json:"detector"`
	Source     string   `json:"source"`
	Line       int      `json:"line,omitempty"` // 1-based line in the top layer, 0 if inside a decoded layer
	Span       Span     `json:"span"`
	Excerpt    string   `json:"excerpt"`
	Message    string   `json:"message"`
	// Chain lists the encodings unwrapped to reach the text this finding is
	// in, outermost first. Empty for findings in the raw text.
	Chain []string `json:"chain,omitempty"`
	// Layer is the decoded text the finding refers to when Chain is non-empty.
	// Kept so sanitizers can show what the blob hides.
	Layer string `json:"-"`
}

// Verdict is the result for one document.
type Verdict struct {
	Source   string    `json:"source"`
	Kind     Kind      `json:"kind"`
	Level    Level     `json:"level"`
	Action   Action    `json:"action"`
	Findings []Finding `json:"findings"`
	// Suppressed holds findings below the policy's confidence floor. They
	// do not affect Level, but the aggregate pass uses them to spot
	// instruction fragments spread thinly across many files.
	Suppressed []Finding `json:"-"`
}

// MarshalText makes Level print as a word in JSON output.
func (l Level) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

// MarshalText makes Action print as a word in JSON output.
func (a Action) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// Detector finds threats in one text layer.
type Detector interface {
	Name() string
	// Detect inspects text and returns findings with Span relative to text.
	// doc gives context (source, kind); text is the layer being inspected,
	// which is doc.Text for the top layer or a decoded blob for deeper ones.
	Detect(doc *Document, text string) []Finding
}

// Policy turns raw findings into the document verdict. Implemented in
// internal/policy; declared here so the scanner has no dependency on it.
type Policy interface {
	Decide(doc *Document, findings []Finding) Verdict
}
