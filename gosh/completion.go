package gosh

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/chzyer/readline"
	"mvdan.cc/sh/v3/interp"
)

type goshAutoCompleter struct {
	ctx           context.Context
	runner        *interp.Runner
	stdin         io.Reader
	stdout        io.Writer
	stderr        io.Writer
	promptPrinter *goshPromptPrinter

	rlMu sync.Mutex
	rl   *readline.Instance

	mu              sync.Mutex
	cachedPath      string
	cachedPathExt   string
	cachedFuncStamp string
	cachedHome      string
	cachedCommands  []string
}

func (c *goshAutoCompleter) attach(rl *readline.Instance) {
	c.rlMu.Lock()
	c.rl = rl
	c.rlMu.Unlock()
}

func (c *goshAutoCompleter) Do(line []rune, pos int) ([][]rune, int) {
	ctx := c.completionContext(line, pos)
	var options []string
	if ctx.isCommand && !strings.ContainsAny(ctx.prefix, "/\\") {
		options = c.commandCandidates(ctx.prefix)
	} else {
		onlyDirs := !ctx.isCommand && strings.EqualFold(ctx.command, "cd")
		options = c.pathCandidates(ctx.prefix, onlyDirs)
	}
	if len(options) == 0 {
		return nil, 0
	}
	prefixLen := utf8.RuneCountInString(ctx.prefix)
	common := goshLongestCommonPrefix(options)
	commonRunes := []rune(common)
	addition := []rune{}
	if len(commonRunes) > prefixLen {
		addition = append(addition, []rune(goshEscapeCompletionForContext(string(commonRunes[prefixLen:]), ctx.quote))...)
	}
	if len(options) == 1 {
		hasTrailingSep := goshHasTrailingPathSeparator(options[0])
		if c.completionOptionIsDir(ctx, options[0]) {
			if !hasTrailingSep {
				addition = append(addition, rune(os.PathSeparator))
			}
		} else if !hasTrailingSep {
			addition = append(addition, ' ')
		}
	}
	if len(addition) > 0 {
		return [][]rune{addition}, prefixLen
	}
	if len(options) == 1 {
		return nil, 0
	}
	c.printMatches(options)
	return nil, 0
}

type goshCompletionContext struct {
	prefix    string
	isCommand bool
	command   string
	quote     rune
}

func (c *goshAutoCompleter) completionContext(line []rune, pos int) goshCompletionContext {
	if pos < 0 {
		pos = 0
	}
	if pos > len(line) {
		pos = len(line)
	}
	return goshScanCompletionContext(line[:pos])
}

func goshScanCompletionContext(line []rune) goshCompletionContext {
	var words []string
	var current []rune
	inWord := false
	quote := rune(0)
	escaped := false
	lastCompleted := ""
	resetCommand := func() {
		words = words[:0]
		lastCompleted = ""
	}
	finishWord := func() {
		if !inWord {
			return
		}
		word := string(current)
		words = append(words, word)
		lastCompleted = word
		current = current[:0]
		inWord = false
	}
	startWord := func() {
		if !inWord {
			inWord = true
			current = current[:0]
		}
	}

	for _, r := range line {
		if escaped {
			startWord()
			current = append(current, r)
			escaped = false
			continue
		}
		if quote == 0 && r == '\\' {
			startWord()
			escaped = true
			continue
		}
		if quote == '"' && r == '\\' {
			startWord()
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				startWord()
				continue
			}
			startWord()
			current = append(current, r)
			continue
		}
		switch {
		case r == '\'' || r == '"':
			startWord()
			quote = r
		case unicode.IsSpace(r):
			finishWord()
		case goshIsCommandSeparator(r):
			finishWord()
			resetCommand()
		default:
			startWord()
			current = append(current, r)
		}
	}

	prefix := ""
	if inWord {
		prefix = string(current)
	}
	isCommand := len(words) == 0
	if inWord {
		isCommand = len(words) == 0 || goshKeywordStartsCommand(lastCompleted)
	} else if lastCompleted != "" && goshKeywordStartsCommand(lastCompleted) {
		isCommand = true
	}
	command := ""
	if len(words) > 0 {
		command = words[0]
	}
	return goshCompletionContext{prefix: prefix, isCommand: isCommand, command: command, quote: quote}
}

func (c *goshAutoCompleter) isCommandPosition(line []rune, start int) bool {
	idx := start - 1
	for idx >= 0 {
		r := line[idx]
		if unicode.IsSpace(r) {
			idx--
			continue
		}
		if goshIsCommandSeparator(r) {
			return true
		}
		end := idx + 1
		for idx >= 0 && !goshIsCompletionBreak(line[idx]) {
			idx--
		}
		word := string(line[idx+1 : end])
		return goshKeywordStartsCommand(word)
	}
	return true
}

func (c *goshAutoCompleter) resolveCommand(line []rune, wordStart int) string {
	idx := wordStart - 1
	for idx >= 0 {
		r := line[idx]
		if r == '\n' {
			break
		}
		if goshIsCommandSeparator(r) {
			break
		}
		idx--
	}
	if idx < 0 {
		idx = 0
	} else {
		idx++
	}
	for idx < len(line) && unicode.IsSpace(line[idx]) {
		idx++
	}
	start := idx
	for idx < len(line) && !goshIsCompletionBreak(line[idx]) {
		idx++
	}
	return string(line[start:idx])
}

func (c *goshAutoCompleter) commandCandidates(prefix string) []string {
	path := c.shellVar("PATH")
	if path == "" {
		path = os.Getenv("PATH")
	}
	pathExt := c.shellVar("PATHEXT")
	if pathExt == "" {
		pathExt = os.Getenv("PATHEXT")
	}
	funcStamp := c.functionStamp()
	home := c.userHome()
	commands := c.commandIndex(path, pathExt, funcStamp, home)
	if len(commands) == 0 {
		return nil
	}
	matches := make([]string, 0, len(commands))
	for _, name := range commands {
		if strings.HasPrefix(name, prefix) {
			matches = append(matches, name)
		}
	}
	return matches
}

func (c *goshAutoCompleter) commandIndex(path, pathExt, funcStamp, home string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if path == c.cachedPath && pathExt == c.cachedPathExt && funcStamp == c.cachedFuncStamp && home == c.cachedHome && len(c.cachedCommands) > 0 {
		return c.cachedCommands
	}
	cmds := c.buildCommandIndexLocked(path, pathExt, home)
	c.cachedPath = path
	c.cachedPathExt = pathExt
	c.cachedFuncStamp = funcStamp
	c.cachedHome = home
	c.cachedCommands = cmds
	return cmds
}

func (c *goshAutoCompleter) buildCommandIndexLocked(path, pathExt, home string) []string {
	seen := make(map[string]struct{})
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
	}
	for _, name := range []string{
		"alias",
		"bg",
		"bind",
		"break",
		"builtin",
		"caller",
		"cd",
		"command",
		"compgen",
		"complete",
		"compopt",
		"continue",
		"declare",
		"dirs",
		"disown",
		"echo",
		"enable",
		"eval",
		"exec",
		"exit",
		"export",
		"false",
		"fc",
		"fg",
		"getopts",
		"hash",
		"help",
		"history",
		"jobs",
		"kill",
		"let",
		"local",
		"logout",
		"mapfile",
		"newgrp",
		"popd",
		"printf",
		"pushd",
		"pwd",
		"read",
		"readarray",
		"readonly",
		"return",
		"set",
		"shift",
		"shopt",
		"source",
		"suspend",
		"test",
		"times",
		"trap",
		"true",
		"type",
		"typeset",
		"ulimit",
		"umask",
		"unalias",
		"unset",
		"wait",
		":",
		".",
		"[",
	} {
		add(name)
	}
	for name := range c.runner.Funcs {
		add(name)
	}
	for _, keyword := range []string{
		"case",
		"coproc",
		"do",
		"done",
		"elif",
		"else",
		"esac",
		"fi",
		"for",
		"function",
		"if",
		"in",
		"select",
		"then",
		"time",
		"until",
		"while",
	} {
		add(keyword)
	}
	if path != "" {
		parts := strings.Split(path, string(os.PathListSeparator))
		for _, dir := range parts {
			if dir == "" {
				dir = "."
			}
			if expanded, ok := goshExpandTilde(dir, home); ok {
				dir = expanded
			}
			if !filepath.IsAbs(dir) {
				base := c.runner.Dir
				if base == "" {
					if wd, err := os.Getwd(); err == nil {
						base = wd
					}
				}
				dir = filepath.Join(base, dir)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				for _, name := range goshCommandEntryNames(dir, entry, runtime.GOOS, pathExt) {
					add(name)
				}
			}
		}
	}
	cmds := make([]string, 0, len(seen))
	for name := range seen {
		cmds = append(cmds, name)
	}
	slices.Sort(cmds)
	return cmds
}

func goshCommandEntryNames(dir string, entry os.DirEntry, goos, pathExt string) []string {
	if entry == nil || entry.IsDir() {
		return nil
	}
	name := entry.Name()
	if goos == "windows" {
		ext := strings.ToLower(filepath.Ext(name))
		if ext == "" || !slices.Contains(goshPathExts(pathExt), ext) {
			return nil
		}
		stem := strings.TrimSuffix(name, filepath.Ext(name))
		if stem == "" || strings.EqualFold(stem, name) {
			return []string{name}
		}
		return []string{stem, name}
	}
	info, err := entry.Info()
	if err == nil && info.Mode()&fs.ModeSymlink != 0 {
		info, err = os.Stat(filepath.Join(dir, name))
	}
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return nil
	}
	return []string{name}
}

func goshPathExts(pathExt string) []string {
	if pathExt == "" {
		pathExt = ".com;.exe;.bat;.cmd"
	}
	var exts []string
	for _, ext := range strings.Split(pathExt, ";") {
		ext = strings.TrimSpace(strings.ToLower(ext))
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		exts = append(exts, ext)
	}
	return exts
}

func (c *goshAutoCompleter) pathCandidates(prefix string, dirsOnly bool) []string {
	dirPart, base := goshSplitPathPrefix(prefix)
	search := dirPart
	if search == "" {
		search = "."
	}
	home := c.userHome()
	if expanded, ok := goshExpandTilde(search, home); ok {
		search = expanded
	}
	clean := filepath.Clean(search)
	if !filepath.IsAbs(clean) {
		cwd := c.runner.Dir
		if cwd == "" {
			if wd, err := os.Getwd(); err == nil {
				cwd = wd
			}
		}
		clean = filepath.Join(cwd, clean)
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return nil
	}
	matches := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		isDir := entry.IsDir()
		if !isDir {
			needStat := dirsOnly || entry.Type()&fs.ModeSymlink != 0
			if needStat {
				if info, err := os.Stat(filepath.Join(clean, name)); err == nil {
					isDir = info.IsDir()
				}
			}
		}
		if dirsOnly && !isDir {
			continue
		}
		candidate := dirPart + name
		if isDir {
			candidate += string(os.PathSeparator)
		}
		matches = append(matches, candidate)
	}
	slices.Sort(matches)
	return matches
}

func (c *goshAutoCompleter) completionOptionIsDir(ctx goshCompletionContext, option string) bool {
	if option == "" {
		return false
	}
	if goshHasTrailingPathSeparator(option) {
		return true
	}
	if ctx.isCommand && !strings.ContainsAny(ctx.prefix, "/\\") {
		return false
	}
	resolved := option
	if expanded, ok := goshExpandTilde(resolved, c.userHome()); ok {
		resolved = expanded
	}
	if !filepath.IsAbs(resolved) {
		base := c.runner.Dir
		if base == "" {
			if wd, err := os.Getwd(); err == nil {
				base = wd
			}
		}
		resolved = filepath.Join(base, resolved)
	}
	if info, err := os.Stat(resolved); err == nil {
		return info.IsDir()
	}
	return false
}

func (c *goshAutoCompleter) printMatches(options []string) {
	if len(options) == 0 || c.stdout == nil {
		return
	}
	width := c.screenWidth()
	if width <= 0 {
		width = 80
	}
	maxLen := 0
	display := make([]string, len(options))
	for i, option := range options {
		display[i] = goshCompletionDisplayName(option)
		if size := utf8.RuneCountInString(display[i]); size > maxLen {
			maxLen = size
		}
	}
	if maxLen == 0 {
		maxLen = 1
	}
	colWidth := maxLen + 2
	if colWidth > width {
		colWidth = maxLen
	}
	cols := 1
	if colWidth > 0 {
		cols = width / colWidth
	}
	if cols < 1 {
		cols = 1
	}
	rows := (len(options) + cols - 1) / cols
	fmt.Fprint(c.stdout, "\r\n")
	for r := 0; r < rows; r++ {
		printed := false
		for cidx := 0; cidx < cols; cidx++ {
			idx := cidx*rows + r
			if idx >= len(options) {
				break
			}
			entry := display[idx]
			printed = true
			fmt.Fprint(c.stdout, entry)
			nextIdx := (cidx+1)*rows + r
			if cidx == cols-1 || nextIdx >= len(options) {
				continue
			}
			pad := colWidth - utf8.RuneCountInString(entry)
			if pad < 1 {
				pad = 1
			}
			fmt.Fprint(c.stdout, strings.Repeat(" ", pad))
		}
		if printed {
			fmt.Fprint(c.stdout, "\r\n")
		}
	}
	c.printPromptPrefix()
	if rl := c.readline(); rl != nil {
		rl.Operation.Refresh()
	}
}

func (c *goshAutoCompleter) readline() *readline.Instance {
	c.rlMu.Lock()
	defer c.rlMu.Unlock()
	return c.rl
}

func (c *goshAutoCompleter) printPromptPrefix() {
	if c.promptPrinter == nil || c.stdout == nil {
		return
	}
	if prefix := c.promptPrinter.Prefix(); prefix != "" {
		fmt.Fprint(c.stdout, prefix)
	}
}

func (c *goshAutoCompleter) screenWidth() int {
	if rl := c.readline(); rl != nil {
		if rl.Config != nil && rl.Config.FuncGetWidth != nil {
			if width := rl.Config.FuncGetWidth(); width > 0 {
				return width
			}
		}
	}
	if width := readline.GetScreenWidth(); width > 0 {
		return width
	}
	return 80
}

func goshCompletionDisplayName(opt string) string {
	trimmed := strings.TrimRight(opt, "/\\")
	if trimmed == "" {
		return goshEscapeCompletion(opt)
	}
	idx := strings.LastIndexAny(trimmed, "/\\")
	base := trimmed
	if idx >= 0 {
		base = trimmed[idx+1:]
	}
	if strings.HasSuffix(opt, "/") || strings.HasSuffix(opt, "\\") {
		base += "/"
	}
	return goshEscapeCompletion(base)
}

func goshEscapeCompletion(val string) string {
	return goshEscapeCompletionForContext(val, 0)
}

func goshEscapeCompletionForContext(val string, quote rune) string {
	if val == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range val {
		if goshShouldEscapeCompletionRune(r, quote) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func goshShouldEscapeCompletionRune(r rune, quote rune) bool {
	switch quote {
	case '\'':
		return r == '\''
	case '"':
		switch r {
		case '\\', '"', '`', '$':
			return true
		default:
			return false
		}
	default:
		switch r {
		case ' ', '\t', '\n', '\\', '"', '\'', '`', '$', '&', '|', ';', '<', '>', '(', ')', '{', '}', '[', ']', '!', '?', '*', '~', '^', '#', '%', '=', ':', ',', '+':
			return true
		default:
			return false
		}
	}
}

func (c *goshAutoCompleter) shellVar(name string) string {
	script := fmt.Sprintf("printf %%s \"${%s-}\"", name)
	val, err := goshRunSubshell(c.ctx, c.runner, c.stdin, c.stderr, script)
	if err == nil && val != "" {
		return val
	}
	return os.Getenv(name)
}

func (c *goshAutoCompleter) userHome() string {
	if home := c.shellVar("HOME"); home != "" {
		return home
	}
	home, _ := os.UserHomeDir()
	return home
}

func (c *goshAutoCompleter) functionStamp() string {
	if len(c.runner.Funcs) == 0 {
		return ""
	}
	names := make([]string, 0, len(c.runner.Funcs))
	for name := range c.runner.Funcs {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, "\x00")
}

func goshSplitPathPrefix(prefix string) (string, string) {
	idx := strings.LastIndexAny(prefix, "/\\")
	if idx < 0 {
		return "", prefix
	}
	return prefix[:idx+1], prefix[idx+1:]
}

func goshHasTrailingPathSeparator(val string) bool {
	if val == "" {
		return false
	}
	return strings.HasSuffix(val, "/") || strings.HasSuffix(val, "\\")
}

func goshIsCompletionBreak(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	switch r {
	case ';', '|', '&', '(', ')', '{', '}', '!':
		return true
	}
	return false
}

func goshIsCommandSeparator(r rune) bool {
	switch r {
	case '|', '&', ';', '(', ')', '{', '}', '!':
		return true
	}
	return false
}

func goshKeywordStartsCommand(word string) bool {
	word = strings.TrimSpace(word)
	if word == "" {
		return false
	}
	for _, kw := range []string{
		"if",
		"then",
		"else",
		"elif",
		"do",
		"done",
		"while",
		"until",
		"time",
		"coproc",
		"fi",
		"esac",
	} {
		if word == kw {
			return true
		}
	}
	return false
}

func goshExpandTilde(path, home string) (string, bool) {
	if !strings.HasPrefix(path, "~") {
		return path, true
	}
	if home == "" {
		return "", false
	}
	if len(path) == 1 {
		return home, true
	}
	next := rune(path[1])
	if next == '/' || next == '\\' {
		if len(path) == 2 {
			return home, true
		}
		return filepath.Join(home, path[2:]), true
	}
	return "", false
}

func goshSharedPrefix(a, b string) string {
	ar := []rune(a)
	br := []rune(b)
	limit := len(ar)
	if len(br) < limit {
		limit = len(br)
	}
	i := 0
	for i < limit && ar[i] == br[i] {
		i++
	}
	return string(ar[:i])
}

func goshLongestCommonPrefix(values []string) string {
	if len(values) == 0 {
		return ""
	}
	prefix := values[0]
	for _, val := range values[1:] {
		prefix = goshSharedPrefix(prefix, val)
		if prefix == "" {
			break
		}
	}
	return prefix
}
