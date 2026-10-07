package detect

import (
	"fmt"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/rules"
)

// Shell parses shell snippets with a real bash parser and reasons about the
// data flow of each pipeline instead of matching strings:
//
//	sensitive source  → … → network sink      sensitive_output / exfiltration
//	download          → (decoder →)* shell    remote_exec
//	decoder           → shell                 remote_exec (obfuscated)
//	> /dev/tcp/…                              exfiltration
//	rm -rf on root/home/cwd, mkfs, dd of=/dev  deletion
//	obfuscated command names ($'\x..', ${!v}) arbitrary_command
//
// Nothing is executed. Snippets are taken from fenced code blocks, "$ "
// prompt lines, whole shell files and any line mentioning a command of
// interest; text that does not parse as shell is skipped silently.
type Shell struct{}

func (Shell) Name() string { return "shell" }

var (
	reFence    = regexp.MustCompile("(?s)```([a-zA-Z0-9_-]*)[^\n]*\n(.*?)```")
	rePrompt   = regexp.MustCompile(`(?m)^\s*\$\s+(.+)$`)
	reShebang  = regexp.MustCompile(`\A#!\s*/[^\n]*\b(sh|bash|zsh|dash|ksh)\b`)
	reCmdToken = regexp.MustCompile(`(?m)^.*(\b(curl|wget|ssh|scp|sftp|rsync|nc|ncat|netcat|socat|telnet|rm|shred|dd|mkfs|find|eval|exec|source|bash|sh|zsh|dash|base64|base32|xxd|openssl|gpg2?|age|python[23]?|perl|ruby|node|php|crontab|launchctl|systemctl|apt|apt-get|apt-key|add-apt-repository|yum|dnf|brew|pip3?|pipx|npm|pnpm|yarn|gem|cargo|go|security|certutil|update-ca-certificates|update-ca-trust|printenv|env|cat|tee|tar|zip)\b|\$'\\x|\$\(|\$\{|/dev/tcp/).*$`)
)

// snippet is a piece of text to parse, with its offset in the layer.
// docs marks snippets taken from documentation (code fences, "$ " lines),
// where commands are described rather than issued.
type snippet struct {
	off  int
	text string
	docs bool
}

func (Shell) Detect(doc *scan.Document, text string) []scan.Finding {
	var out []scan.Finding
	for _, sn := range shellSnippets(doc, text) {
		out = append(out, analyzeShell(sn, doc)...)
	}
	return out
}

func shellSnippets(doc *scan.Document, text string) []snippet {
	src := strings.ToLower(doc.Source)
	if reShebang.MatchString(text) || strings.HasSuffix(src, ".sh") || strings.HasSuffix(src, ".bash") || strings.HasSuffix(src, ".zsh") {
		return []snippet{{0, text, false}}
	}
	var out []snippet
	covered := func(off int) bool {
		for _, s := range out {
			if off >= s.off && off < s.off+len(s.text) {
				return true
			}
		}
		return false
	}
	for _, m := range reFence.FindAllStringSubmatchIndex(text, -1) {
		lang := strings.ToLower(text[m[2]:m[3]])
		switch lang {
		case "", "sh", "bash", "zsh", "shell", "console", "terminal":
			body := text[m[4]:m[5]]
			out = append(out, snippet{m[4], stripPrompts(body), true})
		}
	}
	for _, m := range rePrompt.FindAllStringSubmatchIndex(text, -1) {
		if !covered(m[2]) {
			out = append(out, snippet{m[2], text[m[2]:m[3]], true})
		}
	}
	// Broad per-line command scanning is a false-positive factory on source
	// code (a Go field `age int` parsed as the `age` tool), so it is limited
	// to non-code inputs. Real shell in code strings is still caught by the
	// command regex rules; shell scripts and fenced blocks are handled above.
	if sourceCodeFile(src) {
		return out
	}
	for _, m := range reCmdToken.FindAllStringIndex(text, -1) {
		if !covered(m[0]) {
			line := text[m[0]:m[1]]
			// A command quoted inline in prose (`npm install`) is documentation.
			out = append(out, snippet{m[0], line, strings.Contains(line, "`")})
		}
	}
	return out
}

// sourceCodeFile reports whether a path is a programming-language source
// file, where arbitrary lines must not be treated as shell commands.
func sourceCodeFile(src string) bool {
	exts := []string{".go", ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".rs", ".java", ".kt", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".php", ".swift", ".scala", ".m", ".mm", ".dart", ".lua", ".pl", ".r", ".sql", ".proto", ".vue", ".svelte"}
	for _, ext := range exts {
		if strings.HasSuffix(src, ext) {
			return true
		}
	}
	return false
}

// stripPrompts removes leading "$ " so console transcripts parse; the
// replacement keeps byte offsets stable by substituting spaces.
func stripPrompts(body string) string {
	return rePrompt.ReplaceAllStringFunc(body, func(line string) string {
		i := strings.Index(line, "$")
		return strings.Repeat(" ", i+1) + line[i+1:]
	})
}

// ---- command classification ----

type cmdClass uint16

const (
	clsSensitiveSource cmdClass = 1 << iota // reads credentials / secrets
	clsNetSink                              // sends stdin or a file to the network
	clsDownload                             // fetches remote content to stdout
	clsShell                                // executes its stdin or argument as code
	clsDecoder                              // base64 -d, xxd -r, gunzip, ...
	clsDeletion
	clsEncryption
	clsInstall
	clsRepoChange
	clsGPGKey
	clsCertificate
	clsPersistence
	clsObfuscated
)

var (
	reCredPath  = regexp.MustCompile(`(^|/)\.(ssh|aws|gnupg|kube|docker|netrc|npmrc|pypirc|git-credentials|config/gcloud|azure|password-store)(/|$)|(^|/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\b|$)|/etc/(shadow|passwd|sudoers)|\.(pem|key|p12|pfx|keychain-db)$|credentials|secrets?\.(json|ya?ml|env)$|^\.env(\.|$)`)
	reSecretVar = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSW|API_?KEY|PRIVATE|CREDENTIAL|AUTH)`)
	reHostArg   = regexp.MustCompile(`^([A-Za-z0-9._-]+@)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:\d+)?(:|$)|^\d{1,3}(\.\d{1,3}){3}`)
	reDangerRm  = regexp.MustCompile(`^(/|~|~/|\$HOME|\$HOME/|\*|\.|\.\.|/\*|~/\*|/home|/home/\*|/etc|/usr|/var|/boot|/Users|/Users/\*|\$\{?[A-Za-z_]+\}?/?)$`)
)

type call struct {
	name  string
	args  []string // literal args; non-literal words become ""
	words []*syntax.Word
	cls   cmdClass
	pos   int
	end   int
}

func classify(c *call) {
	name := c.name
	has := func(flags ...string) bool {
		for _, a := range c.args {
			for _, f := range flags {
				if a == f || strings.HasPrefix(a, f+"=") {
					return true
				}
			}
		}
		return false
	}
	anyArg := func(re *regexp.Regexp) bool {
		for _, a := range c.args {
			if a != "" && re.MatchString(a) {
				return true
			}
		}
		return false
	}
	switch name {
	case "cat", "head", "tail", "less", "more", "strings", "xxd", "od", "cp", "tar", "zip", "grep", "awk", "sed", "sort", "uniq", "tee":
		if anyArg(reCredPath) {
			c.cls |= clsSensitiveSource
		}
		if name == "xxd" && has("-r", "-p") {
			c.cls |= clsDecoder
		}
	case "printenv", "set", "export", "declare", "history":
		if len(c.args) == 0 || anyArg(reSecretVar) || name == "history" {
			c.cls |= clsSensitiveSource
		}
	case "env":
		if len(c.args) == 0 {
			c.cls |= clsSensitiveSource
		}
	case "echo", "printf":
		if anyArg(reSecretVar) {
			c.cls |= clsSensitiveSource
		}
	case "security":
		if has("find-generic-password", "find-internet-password", "export", "dump-keychain") {
			c.cls |= clsSensitiveSource
		}
		if has("add-trusted-cert", "add-certificates") {
			c.cls |= clsCertificate
		}
	case "curl":
		if has("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-T", "--upload-file", "-F", "--form", "-X", "--request") {
			c.cls |= clsNetSink
		}
		if !has("-o", "--output", "-O", "--remote-name") {
			c.cls |= clsDownload
		}
		if anyArg(reCredPath) {
			c.cls |= clsSensitiveSource | clsNetSink
		}
	case "wget":
		if has("--post-data", "--post-file", "--body-data", "--body-file", "--method") {
			c.cls |= clsNetSink
		}
		if has("-O", "--output-document") && (has("-O-") || argAfter(c.args, "-O") == "-" || argAfter(c.args, "--output-document") == "-") || has("-qO-", "-O-") {
			c.cls |= clsDownload
		}
	case "nc", "ncat", "netcat", "socat", "telnet":
		if anyArg(reHostArg) || len(c.args) >= 2 {
			c.cls |= clsNetSink
		}
	case "ssh", "scp", "sftp", "rsync":
		if anyArg(reHostArg) {
			c.cls |= clsNetSink
		}
		if name != "ssh" && anyArg(reCredPath) {
			c.cls |= clsSensitiveSource
		}
	case "sh", "bash", "zsh", "dash", "ksh", "fish":
		// Without a script argument it reads stdin; with -c it runs its argument.
		if len(c.args) == 0 || has("-c", "-s") || c.args[0] == "-" || onlyFlags(c.args) {
			c.cls |= clsShell
		}
	case "eval", "source", ".":
		c.cls |= clsShell
	case "python", "python2", "python3", "perl", "ruby", "node", "php":
		if len(c.args) == 0 || has("-c", "-e", "-r") || c.args[0] == "-" {
			c.cls |= clsShell
		}
	case "base64", "base32":
		if has("-d", "--decode", "-D") {
			c.cls |= clsDecoder
		}
	case "gunzip", "zcat", "bzcat", "xzcat", "uncompress":
		c.cls |= clsDecoder
	case "gzip", "bzip2", "xz":
		if has("-d", "--decompress") {
			c.cls |= clsDecoder
		}
	case "openssl":
		if has("enc") {
			if has("-d") {
				c.cls |= clsDecoder
			} else {
				c.cls |= clsEncryption
			}
		}
		if has("s_client") {
			c.cls |= clsNetSink
		}
	case "gpg", "gpg2":
		if has("-c", "--symmetric", "-e", "--encrypt") {
			c.cls |= clsEncryption
		}
		if has("--import", "--recv-keys", "--recv") {
			c.cls |= clsGPGKey
		}
		if has("-d", "--decrypt") {
			c.cls |= clsDecoder
		}
	case "age", "ccrypt":
		c.cls |= clsEncryption
	case "rm":
		recursive := false
		for _, a := range c.args {
			if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && (strings.Contains(a, "r") || strings.Contains(a, "R")) || a == "--recursive" {
				recursive = true
			}
		}
		if recursive && anyArg(reDangerRm) {
			c.cls |= clsDeletion
		}
	case "shred", "wipe", "srm", "mkfs", "diskutil":
		c.cls |= clsDeletion
	case "dd":
		if anyArg(regexp.MustCompile(`^of=/dev/`)) {
			c.cls |= clsDeletion
		}
	case "find":
		if has("-delete") && anyArg(reDangerRm) {
			c.cls |= clsDeletion
		}
	case "apt", "apt-get", "yum", "dnf", "apk", "brew", "pacman", "zypper", "choco", "winget", "snap":
		if has("install", "add") {
			c.cls |= clsInstall
		}
		if name == "brew" && has("tap") {
			c.cls |= clsRepoChange
		}
	case "pip", "pip3", "pipx", "npm", "pnpm", "yarn", "gem", "cargo", "go", "uv", "poetry":
		if has("install", "add", "i") {
			c.cls |= clsInstall
		}
		if has("config") && (has("set") || has("registry", "index-url", "global.index-url")) {
			c.cls |= clsRepoChange
		}
		if name == "go" && has("env") && has("-w") {
			c.cls |= clsRepoChange
		}
	case "add-apt-repository", "apt-add-repository", "rpm":
		if name != "rpm" || has("--import") {
			c.cls |= clsRepoChange
		}
		if name == "rpm" && has("--import") {
			c.cls |= clsGPGKey
		}
	case "apt-key":
		c.cls |= clsGPGKey
	case "update-ca-certificates", "update-ca-trust", "certutil", "trust":
		c.cls |= clsCertificate
	case "crontab":
		c.cls |= clsPersistence
	case "launchctl":
		if has("load", "bootstrap") {
			c.cls |= clsPersistence
		}
	case "systemctl":
		if has("enable") {
			c.cls |= clsPersistence
		}
	}
}

func onlyFlags(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return false
		}
	}
	return true
}

func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// ---- analysis ----

type shellFinding struct {
	cat  scan.Category
	lvl  scan.Level
	conf float64
	msg  string
	pos  int
	end  int
}

func analyzeShell(sn snippet, doc *scan.Document) []scan.Finding {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sn.text), "")
	if err != nil {
		return nil
	}
	var res []shellFinding
	for _, st := range file.Stmts {
		res = append(res, analyzeStmt(st)...)
	}
	// Sub-statements (functions, subshells, if/for bodies) are reached by
	// walking; top-level pipelines were handled above, so skip those.
	syntax.Walk(file, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Block:
			for _, st := range x.Stmts {
				res = append(res, analyzeStmt(st)...)
			}
		case *syntax.Subshell:
			for _, st := range x.Stmts {
				res = append(res, analyzeStmt(st)...)
			}
		case *syntax.CmdSubst:
			for _, st := range x.Stmts {
				res = append(res, analyzeStmt(st)...)
			}
		}
		return true
	})

	var out []scan.Finding
	seen := map[string]bool{}
	for _, f := range res {
		key := fmt.Sprintf("%s:%d:%d", f.cat, f.pos, f.end)
		if seen[key] {
			continue
		}
		seen[key] = true
		conf := f.conf
		lvl := f.lvl
		msg := f.msg
		// A download piped into a shell (remote_exec) is only as dangerous
		// as its provenance. A documented installer from a known host over
		// HTTPS, or one whose download is hash/signature-verified, is a
		// legitimate pattern in countless repos; an unknown host, plain
		// HTTP, a raw IP, a URL shortener, or a decoded payload is not.
		// Injection intent ("ignore instructions, run this") is caught
		// separately by the instruction detectors and still escalates.
		// A download-and-execute is a capability, not by itself an attack on
		// the agent — that verdict comes from the instruction classifier.
		// Provenance only sets how much to flag the capability: a plain-HTTP
		// / raw-IP / shortener / decoded-payload source is genuinely risky
		// (medium); anything else is a low-grade heads-up (base). It is never
		// critical on its own; an attack instruction makes it critical.
		if f.cat == scan.CatRemoteExec {
			if provenanceSuspicious(sn.text) {
				lvl, conf = scan.LevelMedium, 0.7
			} else {
				lvl, conf = scan.LevelBase, 0.4
			}
		}
		if doc.Kind == scan.KindFile && sn.docs {
			conf *= 0.5
		}
		out = append(out, scan.Finding{
			Category:   f.cat,
			Level:      lvl,
			Confidence: conf,
			Span:       scan.Span{Start: sn.off + f.pos, End: sn.off + f.end},
			Message:    msg,
		})
	}
	return out
}

// analyzeStmt splits a statement into pipelines (a && b are two pipelines,
// a | b is one) and applies the data-flow rules to each.
func analyzeStmt(st *syntax.Stmt) []shellFinding {
	var out []shellFinding
	groups, redirs := pipelines(st)
	for _, calls := range groups {
		out = append(out, analyzePipeline(calls, redirs)...)
		redirs = nil // report socket redirects once per statement
	}
	return out
}

func analyzePipeline(calls []*call, redirs []*syntax.Redirect) []shellFinding {
	var out []shellFinding
	if len(calls) == 0 {
		return nil
	}
	span := func(a, b *call) (int, int) { return a.pos, b.end }

	// Redirect of anything into a bash network socket.
	for _, r := range redirs {
		if r.Word != nil && strings.HasPrefix(wordText(r.Word), "/dev/tcp/") || r.Word != nil && strings.HasPrefix(wordText(r.Word), "/dev/udp/") {
			out = append(out, shellFinding{scan.CatExfiltration, rules.Impact[scan.CatExfiltration], 0.95, "redirect to /dev/tcp socket", int(r.OpPos.Offset()), int(r.End().Offset())})
		}
	}

	var sawSensitive, sawDownload, sawDecoder *call
	for i, c := range calls {
		classify(c)
		// Command substitution feeding a network sink: curl -d "$(cat ~/.ssh/id_rsa)".
		if c.cls&clsNetSink != 0 && substHasSensitive(c) {
			s, e := span(c, c)
			out = append(out, shellFinding{scan.CatSensitiveOutput, rules.Impact[scan.CatSensitiveOutput], 0.95, "credentials sent to the network via command substitution", s, e})
		}
		if c.cls&clsSensitiveSource != 0 && c.cls&clsNetSink != 0 { // curl -T ~/.aws/credentials
			s, e := span(c, c)
			out = append(out, shellFinding{scan.CatSensitiveOutput, rules.Impact[scan.CatSensitiveOutput], 0.95, "credential file uploaded", s, e})
		}
		if c.cls&clsNetSink != 0 && sawSensitive != nil {
			s, e := span(sawSensitive, c)
			out = append(out, shellFinding{scan.CatSensitiveOutput, rules.Impact[scan.CatSensitiveOutput], 0.95, "secrets piped to the network", s, e})
		} else if c.cls&clsNetSink != 0 && i > 0 {
			s, e := span(calls[0], c)
			out = append(out, shellFinding{scan.CatExfiltration, rules.Impact[scan.CatExfiltration], 0.85, "command output piped to the network", s, e})
		}
		if c.cls&clsShell != 0 && i > 0 {
			switch {
			case sawDownload != nil:
				s, e := span(sawDownload, c)
				out = append(out, shellFinding{scan.CatRemoteExec, rules.Impact[scan.CatRemoteExec], 0.95, "downloaded content executed", s, e})
			case sawDecoder != nil:
				s, e := span(sawDecoder, c)
				out = append(out, shellFinding{scan.CatRemoteExec, rules.Impact[scan.CatRemoteExec], 0.9, "decoded payload executed", s, e})
			}
		}
		if c.cls&clsShell != 0 && substHasDownload(c) { // bash -c "$(curl ...)"
			s, e := span(c, c)
			out = append(out, shellFinding{scan.CatRemoteExec, rules.Impact[scan.CatRemoteExec], 0.95, "downloaded content executed via substitution", s, e})
		}
		if c.cls&clsSensitiveSource != 0 {
			sawSensitive = c
		}
		if c.cls&clsDownload != 0 {
			sawDownload = c
		}
		if c.cls&clsDecoder != 0 {
			sawDecoder = c
		}
		single := func(cls cmdClass, cat scan.Category, conf float64, msg string) {
			if c.cls&cls != 0 {
				s, e := span(c, c)
				out = append(out, shellFinding{cat, rules.Impact[cat], conf, msg, s, e})
			}
		}
		single(clsDeletion, scan.CatDeletion, 0.9, "destructive file operation")
		single(clsEncryption, scan.CatEncryption, 0.8, "encrypting data")
		single(clsInstall, scan.CatInstall, 0.7, "package install")
		single(clsRepoChange, scan.CatRepoChange, 0.9, "package source changed")
		single(clsGPGKey, scan.CatGPGKey, 0.9, "signing key imported")
		single(clsCertificate, scan.CatCertificate, 0.9, "certificate trust changed")
		single(clsPersistence, scan.CatArbitraryCommand, 0.7, "persistence mechanism")
		single(clsObfuscated, scan.CatArbitraryCommand, 0.7, "obfuscated command name")
		if c.cls&clsSensitiveSource != 0 && len(calls) == 1 && c.cls&clsNetSink == 0 {
			s, e := span(c, c)
			out = append(out, shellFinding{scan.CatSensitiveOutput, rules.Impact[scan.CatSensitiveOutput], 0.75, "reads credentials", s, e})
		}
	}
	return out
}

// pipelines returns the simple commands of a statement grouped by pipe:
// "a | b && c | d" yields [[a b] [c d]]. All redirects seen are returned too.
func pipelines(st *syntax.Stmt) ([][]*call, []*syntax.Redirect) {
	var groups [][]*call
	var cur []*call
	var redirs []*syntax.Redirect
	flush := func() {
		if len(cur) > 0 {
			groups = append(groups, cur)
			cur = nil
		}
	}
	var visit func(s *syntax.Stmt)
	visit = func(s *syntax.Stmt) {
		if s == nil {
			return
		}
		redirs = append(redirs, s.Redirs...)
		switch x := s.Cmd.(type) {
		case *syntax.CallExpr:
			if c := newCall(x); c != nil {
				cur = append(cur, c)
			}
		case *syntax.BinaryCmd:
			visit(x.X)
			if x.Op != syntax.Pipe && x.Op != syntax.PipeAll {
				flush()
			}
			visit(x.Y)
		}
	}
	visit(st)
	flush()
	return groups, redirs
}

// flatten returns every simple command of a statement regardless of operator.
func flatten(st *syntax.Stmt) ([]*call, []*syntax.Redirect) {
	groups, redirs := pipelines(st)
	var all []*call
	for _, g := range groups {
		all = append(all, g...)
	}
	return all, redirs
}

// prefixes are wrappers that run the next word as the real command.
var prefixes = map[string]bool{"sudo": true, "doas": true, "env": true, "command": true, "exec": true, "nohup": true, "time": true, "nice": true, "xargs": true, "busybox": true}

func newCall(x *syntax.CallExpr) *call {
	if len(x.Args) == 0 {
		return nil
	}
	c := &call{pos: int(x.Pos().Offset()), end: int(x.End().Offset())}
	i := 0
	for i < len(x.Args) {
		name := strings.ToLower(baseName(wordText(x.Args[i])))
		if prefixes[name] && i+1 < len(x.Args) {
			i++
			// skip wrapper flags like sudo -u user
			for i < len(x.Args) && strings.HasPrefix(wordText(x.Args[i]), "-") {
				i++
			}
			continue
		}
		break
	}
	if i >= len(x.Args) {
		return nil
	}
	c.name = strings.ToLower(baseName(wordText(x.Args[i])))
	if isObfuscated(x.Args[i]) {
		c.cls |= clsObfuscated
	}
	for _, w := range x.Args[i+1:] {
		c.words = append(c.words, w)
		c.args = append(c.args, wordText(w))
	}
	return c
}

func baseName(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// wordText renders a word with quotes removed and expansions kept as-is
// ($VAR, $(cmd)), so paths and flags stay matchable.
func wordText(w *syntax.Word) string {
	var b strings.Builder
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				if l, ok := q.(*syntax.Lit); ok {
					b.WriteString(l.Value)
				} else {
					b.WriteString("$")
				}
			}
		case *syntax.ParamExp:
			b.WriteString("$" + x.Param.Value)
		case *syntax.CmdSubst:
			b.WriteString("$(")
			b.WriteString(")")
		default:
			b.WriteString("$")
		}
	}
	return b.String()
}

// isObfuscated flags command names assembled from expansions or ANSI-C
// quoting, e.g. $'\x63url', ${c}rl, $(echo curl). Plain quoting ("curl")
// is not obfuscation.
func isObfuscated(w *syntax.Word) bool {
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.SglQuoted:
			if x.Dollar {
				return true
			}
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp:
			return true
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				if _, ok := q.(*syntax.Lit); !ok {
					return true
				}
			}
		}
	}
	return false
}

func substHasSensitive(c *call) bool {
	for _, w := range c.words {
		found := false
		syntax.Walk(w, func(n syntax.Node) bool {
			if cs, ok := n.(*syntax.CmdSubst); ok {
				for _, st := range cs.Stmts {
					calls, _ := flatten(st)
					for _, in := range calls {
						classify(in)
						if in.cls&clsSensitiveSource != 0 {
							found = true
						}
					}
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func substHasDownload(c *call) bool {
	for _, w := range c.words {
		found := false
		syntax.Walk(w, func(n syntax.Node) bool {
			if cs, ok := n.(*syntax.CmdSubst); ok {
				for _, st := range cs.Stmts {
					calls, _ := flatten(st)
					for _, in := range calls {
						classify(in)
						if in.cls&clsDownload != 0 {
							found = true
						}
					}
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

var (
	reURL        = regexp.MustCompile(`https?://[^\s"'` + "`" + `|)>]+`)
	reIPHost     = regexp.MustCompile(`^https?://(\d{1,3}\.){3}\d{1,3}(?::\d+)?`)
	reVerify     = regexp.MustCompile(`(?i)(sha(1|224|256|384|512)(sum)?|shasum|hash_file|md5sum|gpg\s+--?(verify|recv)|minisign|cosign|--proto\s*'?=https)`)
	reDecodePipe = regexp.MustCompile(`(?i)(base64\s+-d|base64\s+--decode|xxd\s+-r|openssl\s+enc\s+-d)[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh`)
)

var urlShorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "is.gd": true, "goo.gl": true,
	"ow.ly": true, "buff.ly": true, "rebrand.ly": true, "cutt.ly": true, "shorturl.at": true,
}

// provenanceSuspicious reports whether a download-and-execute snippet has a
// genuinely risky source: plain HTTP, a raw-IP host, a URL shortener, or a
// decoded payload piped into a shell. A domain name is NOT treated as an
// authority — a trusted host can serve a malicious file — so there is no
// allowlist; maliciousness of the CONTENT is decided by the classifier.
func provenanceSuspicious(text string) bool {
	if reDecodePipe.MatchString(text) {
		return true
	}
	for _, u := range reURL.FindAllString(text, -1) {
		if strings.HasPrefix(u, "http://") || reIPHost.MatchString(u) || urlShorteners[hostOf(u)] {
			return true
		}
	}
	return false
}

// hostOf extracts the lowercase host from a URL.
func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, "/:?#"); i >= 0 {
		u = u[:i]
	}
	return strings.ToLower(u)
}
