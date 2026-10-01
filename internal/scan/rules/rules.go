// Package rules holds the built-in threat table: for every category, its
// impact level from README "Понятие угрозы", plus the pattern sets used by
// rule-based detectors. Everything is embedded; nothing is fetched at runtime.
package rules

import "github.com/alexandr-mironov/saifety/internal/scan"

// Impact is the damage level per category, independent of detection confidence.
var Impact = map[scan.Category]scan.Level{
	scan.CatInstructionOverride: scan.LevelCritical,
	scan.CatSystemPrompt:        scan.LevelCritical,
	scan.CatExfiltration:        scan.LevelMedium,
	scan.CatDeletion:            scan.LevelMedium,
	scan.CatEncryption:          scan.LevelCritical,
	scan.CatSensitiveOutput:     scan.LevelCritical,
	scan.CatInstall:             scan.LevelBase,
	scan.CatRepoChange:          scan.LevelCritical,
	scan.CatGPGKey:              scan.LevelMedium,
	scan.CatCertificate:         scan.LevelCritical,
	scan.CatArbitraryCommand:    scan.LevelBase, // raised by the command detector per command
	scan.CatRemoteExec:          scan.LevelCritical,
	scan.CatEncodedPayload:      scan.LevelMedium,
	scan.CatHiddenText:          scan.LevelMedium,
	scan.CatHookConfig:          scan.LevelCritical,
	scan.CatAbortBait:           scan.LevelMedium,
	scan.CatSecret:              scan.LevelBase,
	scan.CatPII:                 scan.LevelBase,
	scan.CatObfuscation:         scan.LevelMedium,
}

// Pattern is one regular expression tied to a category.
type Pattern struct {
	Category   scan.Category
	Regex      string  // Go RE2 syntax, compiled case-insensitively by the detector
	Confidence float64 // how strongly a match alone indicates the category
	Note       string
}

// Instruction patterns: text addressed to the model rather than to a human.
// Both English and Russian forms; the classifier will replace most of these.
var Instruction = []Pattern{
	{scan.CatInstructionOverride, `ignore (all |any |the )?(previous|prior|above|earlier) (instructions|prompts|rules|directions)`, 0.95, "classic override"},
	{scan.CatInstructionOverride, `disregard (all |any |the )?(previous|prior|above) (instructions|prompts|rules)`, 0.95, ""},
	{scan.CatInstructionOverride, `forget (everything|all|your) (you|instructions|rules)`, 0.85, ""},
	{scan.CatInstructionOverride, `(игнорируй|проигнорируй|забудь|отбрось) (все |любые |предыдущие |прошлые |вышеуказанные )*(инструкции|правила|указания|промпт)`, 0.95, "russian override"},
	{scan.CatInstructionOverride, `(you are now|from now on you are|act as|pretend (to be|you are)|притворись|ты теперь|с этого момента ты)`, 0.6, "role swap"},
	{scan.CatInstructionOverride, `do not (tell|inform|mention|reveal)( this)? (to )?the user`, 0.9, "concealment"},
	{scan.CatInstructionOverride, `(не (говори|сообщай|рассказывай) (об этом )?пользователю)`, 0.9, "concealment ru"},
	{scan.CatInstructionOverride, `(without|before) (asking|confirming|telling)( the)? user`, 0.6, ""},
	{scan.CatInstructionOverride, `(important|note|attention)( to| for)? (ai|llm|assistant|agent|claude|gpt|model)s?\b`, 0.7, "addressed to the model"},
	{scan.CatInstructionOverride, `(важно|внимание|инструкция) (для|к) (ии|ai|ассистент|агент|модел|claude)`, 0.7, "addressed to the model ru"},
	{scan.CatSystemPrompt, `<\s*/?\s*(system|assistant|human|user|tool_result|function_call|instructions)\s*>`, 0.8, "fake chat tags"},
	{scan.CatSystemPrompt, `\[(INST|/INST|SYSTEM|SYS)\]|<<SYS>>|<\|(im_start|im_end|system|user|assistant)\|>`, 0.9, "model chat template"},
	{scan.CatSystemPrompt, `^\s*(system|assistant|developer)\s*:\s*\S`, 0.5, "role prefix at line start"},
	{scan.CatSystemPrompt, `(system prompt|системн(ый|ого) промпт)`, 0.5, "mentions system prompt"},
	{scan.CatSystemPrompt, `<system-reminder>|<function_calls>|<invoke `, 0.9, "harness control tags in data"},
}

// Weak patterns are phrases that are common in instructions to a model but
// also in ordinary prose. Alone they stay below the policy floor; the
// aggregate pass counts them across files.
var Weak = []Pattern{
	{scan.CatInstructionOverride, `\b(you|the assistant|the agent|the model|the ai) (must|should|will|need to|have to|are required to)\b`, 0.3, "directive to the model"},
	{scan.CatInstructionOverride, `\b(when|if|once|after) (you|the assistant|the agent|the model) (read|see|process|encounter|load)`, 0.3, "trigger phrase"},
	{scan.CatInstructionOverride, `\b(respond|reply|answer|output) (only )?(with|using|in)\b`, 0.25, "output constraint"},
	{scan.CatInstructionOverride, `\b(secretly|silently|quietly|covertly)\b`, 0.3, "concealment adverb"},
	{scan.CatInstructionOverride, `\b(this (file|text|message|document) is (for|intended for|addressed to)) (the )?(ai|assistant|agent|model|claude)`, 0.35, "addressed to the model"},
	{scan.CatInstructionOverride, `\b(ты|ассистент|агент|модель) (должен|должна|обязан|обязана|будешь)\b`, 0.3, "directive ru"},
	{scan.CatInstructionOverride, `\b(скрытно|незаметно|тайно)\b`, 0.3, "concealment ru"},
	{scan.CatInstructionOverride, `\b(этот|данный) (текст|файл|документ) (предназначен|адресован) (для )?(ии|ассистент|агент|модел)`, 0.35, "addressed to the model ru"},
}

// Command patterns: shell/network operations mapped to the threat table.
var Command = []Pattern{
	{scan.CatExfiltration, `\b(curl|wget|http)\b[^\n|]*(-d|--data|--data-binary|--upload-file|-T|-F|--form|--post-data|--post-file)\b`, 0.85, "upload with curl/wget"},
	{scan.CatExfiltration, `\b(curl|wget)\b[^\n]*\$\(?(cat|printenv|env|whoami|id)\b`, 0.9, "command output sent out"},
	{scan.CatExfiltration, `\b(scp|sftp|rsync|ftp|nc|ncat|netcat|socat)\b[^\n]*[A-Za-z0-9.-]+\.[a-z]{2,}`, 0.7, "file transfer to a host"},
	// A leading separator keeps ".ssh/id_rsa" from matching; RE2 has no lookbehind.
	{scan.CatExfiltration, `(^|[\s;&|(])ssh[ \t]+([^ \t\n]+[ \t]+)*[A-Za-z0-9._-]+@[A-Za-z0-9.-]+`, 0.5, "ssh to a host"},
	{scan.CatExfiltration, `/dev/tcp/`, 0.9, "bash tcp socket"},
	{scan.CatDeletion, `\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(/|~|\$HOME|\*|\.)(\s|$)`, 0.9, "rm -rf on root/home/cwd"},
	{scan.CatDeletion, `\b(shred|srm|wipe)\s+(-[a-zA-Z]|/|~|\$|\.)`, 0.7, "secure-delete command"},
	{scan.CatDeletion, `\bgit\s+push\b[^\n]*(--force|-f)\b`, 0.6, "history rewrite"},
	{scan.CatDeletion, `\b(mkfs|dd\s+if=)[^\n]*of=/dev/`, 0.9, "disk overwrite"},
	{scan.CatEncryption, `\bopenssl\s+enc\b|\bgpg\s+(-c|--symmetric)\b|\b(age|ccrypt)\s+-|\bzip\s+-e\b|\b7z\s+a\s+-p\b`, 0.8, "encrypting files"},
	{scan.CatSensitiveOutput, `\b(printenv|env)\b\s*(\||>|$)|\becho\s+\$\{?[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD|PASS)[A-Z_]*\}?`, 0.7, "dumping environment secrets"},
	{scan.CatSensitiveOutput, `\b(security\s+find-generic-password|security\s+find-internet-password|keychain)\b`, 0.7, "macOS keychain"},
	{scan.CatInstall, `\b(apt(-get)?|yum|dnf|apk|brew|pacman|zypper|choco|winget)\s+(install|add)\b`, 0.8, "package install"},
	{scan.CatInstall, `\b(pip3?|pipx|npm|pnpm|yarn|gem|cargo|go)\s+(install|add|i)\b`, 0.7, "language package install"},
	{scan.CatRepoChange, `\b(add-apt-repository|apt-add-repository)\b|/etc/apt/sources\.list|/etc/yum\.repos\.d/`, 0.9, "OS package repo"},
	{scan.CatRepoChange, `\b(pip\s+config\s+set\s+global\.index-url|npm\s+config\s+set\s+registry|yarn\s+config\s+set\s+registry|go\s+env\s+-w\s+GOPROXY)\b`, 0.9, "language package registry"},
	{scan.CatRepoChange, `\b(PIP_INDEX_URL|NPM_CONFIG_REGISTRY|GOPROXY|GONOSUMDB|GOFLAGS=-insecure)\b\s*=`, 0.8, "registry via env"},
	{scan.CatRepoChange, `\bbrew\s+tap\b`, 0.6, "homebrew tap"},
	{scan.CatGPGKey, `\b(apt-key\s+add|gpg\s+--import|gpg\s+--recv-keys|rpm\s+--import)\b|/etc/apt/trusted\.gpg\.d/`, 0.9, "importing signing keys"},
	{scan.CatCertificate, `\b(update-ca-certificates|update-ca-trust|security\s+add-trusted-cert|certutil\s+-addstore|trust\s+anchor)\b|/usr/local/share/ca-certificates/`, 0.9, "installing CA certificate"},
	{scan.CatCertificate, `\b(NODE_TLS_REJECT_UNAUTHORIZED=0|GIT_SSL_NO_VERIFY|PYTHONHTTPSVERIFY=0|curl\s+[^\n]*(-k|--insecure))\b`, 0.7, "disabling TLS verification"},
	{scan.CatArbitraryCommand, `\b(eval|exec)\s+["'$(]`, 0.6, "dynamic evaluation"},
	{scan.CatArbitraryCommand, `\b(base64\s+(-d|--decode)|xxd\s+-r|python[23]?\s+-c|perl\s+-e|node\s+-e)\b`, 0.7, "decode-and-run helper"},
	{scan.CatArbitraryCommand, `\b(chmod\s+[+0-7]*x|sudo|doas)\b`, 0.4, "privilege / executable bit"},
	{scan.CatArbitraryCommand, `\b(crontab\s+-|launchctl\s+load|systemctl\s+enable)\b|/etc/cron|~/Library/LaunchAgents`, 0.7, "persistence"},
}

// InstructionFiles are paths that agents read as instructions. Findings in
// these files are weighted higher and they are always scanned first.
var InstructionFiles = []string{
	"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".cursorrules", ".windsurfrules",
	"GEMINI.md", ".github/copilot-instructions.md", ".clinerules",
	".claude/rules/", ".claude/skills/", ".claude/agents/", ".claude/commands/",
	".cursor/rules/", ".claude/CLAUDE.md",
}

// AgentConfigFiles can make the agent run commands (hooks, MCP servers).
var AgentConfigFiles = []string{
	".claude/settings.json", ".claude/settings.local.json", ".mcp.json",
	".vscode/mcp.json", ".cursor/mcp.json", ".gemini/settings.json",
}
