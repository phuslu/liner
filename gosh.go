package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/chzyer/readline"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func gosh(ctx context.Context, isatty bool, stdin io.Reader, stdout, stderr io.Writer) error {
	signals := []os.Signal{syscall.SIGTERM}
	if !isatty {
		signals = append(signals, os.Interrupt)
	}
	ctx, cancel := signal.NotifyContext(ctx, signals...)
	defer cancel()

	SetProcessName(os.Args[0])

	if exe, err := exec.LookPath("bash"); err == nil {
		os.Setenv("SHELL", exe)
	} else {
		switch runtime.GOOS {
		case "windows":
			os.Setenv("SHELL", "cmd.exe")
		default:
			os.Setenv("SHELL", "/bin/sh")
		}
	}

	parser := syntax.NewParser()
	history := &goshHistory{limit: goshResolveHistoryLimit()}
	bindings := &goshKeyBindingManager{entries: make(map[string]*goKeyBindingEntry)}
	runner, err := interp.New(
		interp.Interactive(true),
		interp.StdIO(stdin, stdout, stderr),
		interp.ExecHandlers(
			goshHistoryExecMiddleware(history),
			goshBindExecMiddleware(bindings),
		),
	)
	if err != nil {
		return err
	}
	goshInstallShellOptionVariable(runner, isatty, stdin != nil)

	// source the init files.
	if file, err := os.Open(cmp.Or(os.Getenv("GOSH_ENV"), os.ExpandEnv("$HOME/.profile"))); err == nil {
		prog, err := parser.Parse(file, file.Name())
		if err != nil {
			fmt.Fprintln(stderr, "failed to parse", file.Name(), ":", err)
		} else {
			if err := runner.Run(ctx, prog); err != nil {
				fmt.Fprintln(stderr, "failed to run", file.Name(), ":", err)
			}
		}
		file.Close()
	}

	defaultPrompt := goshDefaultPrompt()
	promptSeq := 1
	currentPrompt := goshPromptString(ctx, runner, stdin, stderr, "PS1", defaultPrompt, promptSeq)
	promptSeq++

	// Non-interactive: parse stdin as a script and run it directly.
	if !isatty {
		prog, err := parser.Parse(stdin, "")
		if err != nil {
			return err
		}
		runner.Reset()
		return runner.Run(ctx, prog)
	}

	// bash -c "xxxx"
	if slices.Contains(os.Args, "-c") {
		return fmt.Errorf("gosh: cannot support -c option: %q", os.Args)
	}

	// export HISTFILE=""
	histFile, ok := os.LookupEnv("HISTFILE")
	switch {
	case !ok:
		histFile = os.ExpandEnv("$HOME/.ash_history")
	case histFile == os.DevNull || histFile == "/dev/null":
		histFile = ""
	}

	boundStdin := &goshKeyBindingInput{src: stdin, mgr: bindings}
	promptPrinter := &goshPromptPrinter{}
	rlStdout := cmp.Or(stdout.(*os.File), os.Stdout)
	rlStderr := cmp.Or(stderr.(*os.File), os.Stderr)
	completer := &goshAutoCompleter{ctx: ctx, runner: runner, stdin: stdin, stderr: stderr, stdout: rlStdout, promptPrinter: promptPrinter}
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          currentPrompt.prompt,
		HistoryFile:     histFile,
		HistoryLimit:    history.limit,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		Stdin:           readline.NewCancelableStdin(boundStdin),
		Stdout:          rlStdout,
		Stderr:          rlStderr,
		AutoComplete:    completer,
		FuncGetWidth: func() int {
			if w := readline.GetScreenWidth(); w > 0 {
				return w
			}
			return 80
		},
	})
	if err != nil {
		return err
	}
	completer.attach(rl)
	defer rl.Close()
	promptPrinter.Print(rl.Stdout(), currentPrompt.prefix)
	nextPrefix := ""
	setPrompt := func(parts goshPromptParts) {
		rl.SetPrompt(parts.prompt)
		nextPrefix = parts.prefix
	}
	flushPrefix := func() {
		if nextPrefix == "" {
			return
		}
		promptPrinter.Print(rl.Stdout(), nextPrefix)
		nextPrefix = ""
	}

	// goshReader wraps readline so parser.Interactive can consume it as an
	// io.Reader. Each call to Read invokes Readline() to fetch one line.
	// Ctrl-C (ErrInterrupt) injects a newline to abandon the current
	// incomplete statement. Ctrl-D / EOF returns io.EOF to end the session.
	rdr := &goshReader{rl: rl, history: history}

	return parser.Interactive(rdr, func(stmts []*syntax.Stmt) bool {
		// parser.Incomplete() returns true when the parser has consumed a
		// partial statement and is waiting for more input (e.g. open quotes,
		// unclosed if/for blocks). Switch to the continuation prompt and keep
		// reading without executing anything yet.
		if parser.Incomplete() {
			setPrompt(goshPromptString(ctx, runner, stdin, stderr, "PS2", "> ", promptSeq))
			flushPrefix()
			return true
		}

		for _, stmt := range stmts {
			if err := runner.Run(ctx, stmt); err != nil {
				var status interp.ExitStatus
				if errors.As(err, &status) {
					continue
				}
				fmt.Fprintln(rl.Stdout(), err.Error())
			}
			if runner.Exited() {
				return false
			}
		}

		// Restore the main prompt, updating it in case the effective UID
		// changed (e.g. via su).
		setPrompt(goshPromptString(ctx, runner, stdin, stderr, "PS1", goshDefaultPrompt(), promptSeq))
		promptSeq++
		flushPrefix()
		return true
	})
}

// goshReader adapts *readline.Instance to the io.Reader interface expected by
// parser.Interactive. The parser calls Read whenever it needs more input.
type goshReader struct {
	rl      *readline.Instance
	buf     []byte // leftover bytes from the previous Readline call
	history *goshHistory
}

func (r *goshReader) Read(p []byte) (int, error) {
	// Drain any bytes that did not fit into p on the previous call.
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	line, err := r.rl.Readline()
	if err != nil {
		if err == readline.ErrInterrupt {
			// Ctrl-C: feed a bare newline so the parser discards the current
			// incomplete statement and returns to a clean state.
			p[0] = '\n'
			return 1, nil
		}
		// Ctrl-D or any other error: signal EOF to shut down the parser loop.
		return 0, io.EOF
	}

	if r.history != nil {
		r.history.Add(line)
	}
	data := []byte(line + "\n")
	n := copy(p, data)
	if n < len(data) {
		r.buf = data[n:] // stash the remainder for the next Read call
	}
	return n, nil
}

type goshHistory struct {
	limit   int
	mu      sync.Mutex
	entries []string
}

func goshResolveHistoryLimit() int {
	val, ok := os.LookupEnv("HISTSIZE")
	if ok {
		if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && n > 0 {
			return n
		}
	}
	return 1000
}

func (h *goshHistory) Add(line string) {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, line)
	if h.limit > 0 && len(h.entries) > h.limit {
		h.entries = h.entries[len(h.entries)-h.limit:]
	}
}

func (h *goshHistory) Entries() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.entries))
	copy(out, h.entries)
	return out
}

func goshDefaultPrompt() string {
	if os.Geteuid() == 0 {
		return "# "
	}
	return "$ "
}

func goshPromptString(ctx context.Context, runner *interp.Runner, stdin io.Reader, stderr io.Writer, name, fallback string, seq int) goshPromptParts {
	host := "localhost"
	if h, err := os.Hostname(); err == nil {
		host = h
	}
	short := host
	if idx := strings.IndexByte(host, '.'); idx >= 0 {
		short = host[:idx]
	}
	state := &goshPromptState{
		ctx:       ctx,
		runner:    runner,
		stdin:     stdin,
		stderr:    stderr,
		dir:       runner.Dir,
		host:      host,
		shortHost: short,
		seq:       seq,
		now:       time.Now(),
	}
	val, err := state.runScript(fmt.Sprintf("printf %%s \"${%s-}\"", name))
	if err != nil || val == "" {
		return goshPromptParts{prompt: fallback}
	}
	return goshSplitPromptLines((&goshPromptRenderer{src: val, state: state}).render())
}

type goshPromptParts struct {
	prefix string
	prompt string
}

type goshPromptPrinter struct {
	mu     sync.RWMutex
	prefix string
}

func (p *goshPromptPrinter) Print(w io.Writer, prefix string) {
	p.mu.Lock()
	p.prefix = prefix
	p.mu.Unlock()
	if prefix == "" || w == nil {
		return
	}
	fmt.Fprint(w, prefix)
}

func (p *goshPromptPrinter) Prefix() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.prefix
}

func goshSplitPromptLines(val string) goshPromptParts {
	idx := strings.LastIndexByte(val, '\n')
	if idx < 0 {
		return goshPromptParts{prompt: val}
	}
	return goshPromptParts{
		prefix: val[:idx+1],
		prompt: val[idx+1:],
	}
}

type goshPromptState struct {
	ctx       context.Context
	runner    *interp.Runner
	stdin     io.Reader
	stderr    io.Writer
	vars      map[string]string
	dir       string
	host      string
	shortHost string
	seq       int
	now       time.Time
}

func (p *goshPromptState) shellVar(name string) string {
	if p.vars == nil {
		p.vars = make(map[string]string)
	}
	if val, ok := p.vars[name]; ok {
		return val
	}
	script := fmt.Sprintf("printf %%s \"${%s-}\"", name)
	val, err := p.runScript(script)
	if err != nil {
		val = ""
	}
	p.vars[name] = val
	return val
}

func (p *goshPromptState) user() string {
	if val := p.shellVar("USER"); val != "" {
		return val
	}
	if val := os.Getenv("USER"); val != "" {
		return val
	}
	return fmt.Sprintf("%d", os.Getuid())
}

func (p *goshPromptState) home() string {
	if val := p.shellVar("HOME"); val != "" {
		return val
	}
	home, _ := os.UserHomeDir()
	return home
}

func (p *goshPromptState) pwd() string {
	if p.dir == "" {
		p.dir = p.shellVar("PWD")
	}
	if p.dir == "" {
		p.dir = "."
	}
	return p.dir
}

func (p *goshPromptState) promptSymbol() string {
	if os.Geteuid() == 0 {
		return "#"
	}
	return "$"
}

type goshPromptRenderer struct {
	src   string
	state *goshPromptState
}

func (r *goshPromptRenderer) render() string {
	var b strings.Builder
	for i := 0; i < len(r.src); {
		switch r.src[i] {
		case '\\':
			if i+1 >= len(r.src) {
				b.WriteByte('\\')
				i++
				continue
			}
			next := r.src[i+1]
			if next == '[' {
				inner, pos := r.scanNonPrinting(i + 2)
				if pos == -1 {
					i += 2
					continue
				}
				b.WriteString((&goshPromptRenderer{src: inner, state: r.state}).render())
				i = pos
				continue
			}
			if next == ']' {
				i += 2
				continue
			}
			val, pos := r.handleEscape(i + 1)
			b.WriteString(val)
			i = pos
		case '$':
			val, next := r.expandDollar(i)
			if next == i {
				b.WriteByte('$')
				i++
				continue
			}
			b.WriteString(val)
			i = next
		default:
			b.WriteByte(r.src[i])
			i++
		}
	}
	return b.String()
}

func (r *goshPromptRenderer) scanNonPrinting(start int) (string, int) {
	for i := start; i < len(r.src)-1; i++ {
		if r.src[i] == '\\' && r.src[i+1] == ']' {
			return r.src[start:i], i + 2
		}
	}
	return "", -1
}

func (r *goshPromptRenderer) handleEscape(idx int) (string, int) {
	c := r.src[idx]
	switch c {
	case 'a':
		return "\a", idx + 1
	case 'e', 'E':
		return "\x1b", idx + 1
	case 'n':
		return "\n", idx + 1
	case 'r':
		return "\r", idx + 1
	case 't':
		return r.state.now.Format("15:04:05"), idx + 1
	case 'T':
		return r.state.now.Format("03:04:05"), idx + 1
	case '@':
		return r.state.now.Format("03:04:05PM"), idx + 1
	case 'A':
		return r.state.now.Format("15:04"), idx + 1
	case 'd':
		return r.state.now.Format("Mon Jan 02"), idx + 1
	case 's':
		return "gosh", idx + 1
	case 'u':
		return r.state.user(), idx + 1
	case 'h':
		return r.state.shortHost, idx + 1
	case 'H':
		return r.state.host, idx + 1
	case 'w':
		return r.state.displayPwd(), idx + 1
	case 'W':
		return filepath.Base(r.state.displayPwd()), idx + 1
	case 'D':
		if idx+1 < len(r.src) && r.src[idx+1] == '{' {
			end := strings.IndexByte(r.src[idx+2:], '}')
			if end >= 0 {
				start := idx + 2
				format := r.src[start : start+end]
				return r.state.formatTime(format), start + end + 1
			}
		}
	case '#', '!':
		return fmt.Sprintf("%d", r.state.seq), idx + 1
	case '\\':
		return "\\", idx + 1
	case '$':
		return r.state.promptSymbol(), idx + 1
	case '0':
		return "\000", idx + 1
	case 'j':
		return "0", idx + 1
	case 'v', 'V':
		return "gosh", idx + 1
	}
	return string(c), idx + 1
}

func (r *goshPromptRenderer) expandDollar(i int) (string, int) {
	if i+1 >= len(r.src) {
		return "", i
	}
	switch r.src[i+1] {
	case '(':
		if i+2 < len(r.src) && r.src[i+2] == '(' {
			expr, end, ok := r.scanArithmetic(i + 3)
			if !ok {
				return "", i
			}
			return r.state.runArithmetic(expr), end
		}
		body, end, ok := r.scanDelimited(i+2, '(', ')')
		if !ok {
			return "", i
		}
		return r.state.runCommand(body), end
	case '{':
		body, end, ok := r.scanDelimited(i+2, '{', '}')
		if !ok {
			return "", i
		}
		expr := "${" + body + "}"
		return r.state.runParam(expr), end
	default:
		name, end := r.scanName(i + 1)
		if end == i+1 {
			return "", i
		}
		expr := fmt.Sprintf("${%s-}", name)
		return r.state.runParam(expr), end
	}
}

func (r *goshPromptRenderer) scanName(start int) (string, int) {
	if start >= len(r.src) {
		return "", start
	}
	ch := r.src[start]
	if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' {
		j := start + 1
		for j < len(r.src) {
			c := r.src[j]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
				j++
				continue
			}
			break
		}
		return r.src[start:j], j
	}
	if strings.ContainsRune("@*#?$!-0123456789", rune(ch)) {
		return r.src[start : start+1], start + 1
	}
	return "", start
}

func (r *goshPromptRenderer) scanDelimited(start int, open, close byte) (string, int, bool) {
	depth := 1
	for i := start; i < len(r.src); i++ {
		s := r.src[i]
		switch s {
		case '\\':
			i++
			continue
		case '\'':
			j := i + 1
			for j < len(r.src) && r.src[j] != '\'' {
				j++
			}
			if j >= len(r.src) {
				return "", len(r.src), false
			}
			i = j
			continue
		case '"':
			j := i + 1
			for j < len(r.src) {
				if r.src[j] == '\\' && j+1 < len(r.src) {
					j += 2
					continue
				}
				if r.src[j] == '"' {
					break
				}
				j++
			}
			if j >= len(r.src) {
				return "", len(r.src), false
			}
			i = j
			continue
		case '$':
			if open == '(' && close == ')' && i+2 < len(r.src) && r.src[i+1] == '(' && r.src[i+2] == '(' {
				next, ok := r.skipArithmetic(i + 3)
				if !ok {
					return "", len(r.src), false
				}
				i = next - 1
				continue
			}
		}
		if s == open {
			depth++
			continue
		}
		if s == close {
			depth--
			if depth == 0 {
				return r.src[start:i], i + 1, true
			}
		}
	}
	return "", len(r.src), false
}

func (r *goshPromptRenderer) scanArithmetic(start int) (string, int, bool) {
	body, end, ok := r.scanDelimited(start, '(', ')')
	if !ok || end >= len(r.src) {
		return "", len(r.src), false
	}
	return body, end + 1, true
}

func (r *goshPromptRenderer) skipArithmetic(start int) (int, bool) {
	_, end, ok := r.scanDelimited(start, '(', ')')
	if !ok || end >= len(r.src) || r.src[end] != ')' {
		return len(r.src), false
	}
	return end + 1, true
}

func (p *goshPromptState) displayPwd() string {
	dir := p.pwd()
	home := p.home()
	if home != "" {
		if dir == home {
			return "~"
		}
		prefix := home
		if !strings.HasSuffix(prefix, string(os.PathSeparator)) {
			prefix += string(os.PathSeparator)
		}
		if strings.HasPrefix(dir, prefix) {
			return "~" + dir[len(home):]
		}
	}
	return dir
}

func (p *goshPromptState) formatTime(layout string) string {
	var b strings.Builder
	for i := 0; i < len(layout); i++ {
		if layout[i] != '%' {
			b.WriteByte(layout[i])
			continue
		}
		i++
		if i >= len(layout) {
			b.WriteByte('%')
			break
		}
		switch layout[i] {
		case '%':
			b.WriteByte('%')
		case 'H':
			b.WriteString(fmt.Sprintf("%02d", p.now.Hour()))
		case 'M':
			b.WriteString(fmt.Sprintf("%02d", p.now.Minute()))
		case 'S':
			b.WriteString(fmt.Sprintf("%02d", p.now.Second()))
		case 'Y':
			b.WriteString(fmt.Sprintf("%04d", p.now.Year()))
		case 'm':
			b.WriteString(fmt.Sprintf("%02d", int(p.now.Month())))
		case 'd':
			b.WriteString(fmt.Sprintf("%02d", p.now.Day()))
		case 'F':
			b.WriteString(p.now.Format("2006-01-02"))
		case 'T':
			b.WriteString(p.now.Format("15:04:05"))
		case 'R':
			b.WriteString(p.now.Format("15:04"))
		case 'z':
			b.WriteString(p.now.Format("-0700"))
		case 'Z':
			b.WriteString(p.now.Format("MST"))
		default:
			b.WriteByte('%')
			b.WriteByte(layout[i])
		}
	}
	return b.String()
}

func (p *goshPromptState) runCommand(cmd string) string {
	out, err := p.runScript(cmd)
	if err != nil {
		return ""
	}
	return out
}

func (p *goshPromptState) runParam(expr string) string {
	script := fmt.Sprintf("printf %%s \"%s\"", p.escapeDouble(expr))
	out, err := p.runScript(script)
	if err != nil {
		return ""
	}
	return out
}

func (p *goshPromptState) runArithmetic(expr string) string {
	script := fmt.Sprintf("printf %%s \"$((%s))\"", p.escapeDouble(expr))
	out, err := p.runScript(script)
	if err != nil {
		return ""
	}
	return out
}

func (p *goshPromptState) runScript(script string) (string, error) {
	return goshRunSubshell(p.ctx, p.runner, p.stdin, p.stderr, script)
}

func goshRunSubshell(ctx context.Context, runner *interp.Runner, stdin io.Reader, stderr io.Writer, script string) (string, error) {
	prog, err := syntax.NewParser().Parse(strings.NewReader(script), "")
	if err != nil {
		return "", err
	}
	sub := runner.Subshell()
	var buf bytes.Buffer
	interp.StdIO(stdin, &buf, stderr)(sub)
	if err := sub.Run(ctx, prog); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

func (p *goshPromptState) escapeDouble(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

func goshHistoryExecMiddleware(history *goshHistory) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) > 0 && args[0] == "history" && history != nil {
				hc := interp.HandlerCtx(ctx)
				entries := history.Entries()
				for idx, entry := range entries {
					fmt.Fprintf(hc.Stdout, "%5d  %s\n", idx+1, entry)
				}
				return nil
			}
			return next(ctx, args)
		}
	}
}

func goshInstallShellOptionVariable(runner *interp.Runner, interactive, readFromStdin bool) {
	if runner == nil {
		return
	}
	base := runner.Env
	if base == nil {
		base = expand.ListEnviron()
	}
	provider := &goshShellOptionProvider{
		runner:        runner,
		interactive:   interactive,
		readFromStdin: readFromStdin,
	}
	runner.Env = &goshShellEnviron{base: base, flags: provider.Flags}
}

type goshShellEnviron struct {
	base  expand.Environ
	flags func() string
}

func (e *goshShellEnviron) Get(name string) expand.Variable {
	if name == "-" {
		return expand.Variable{Set: true, Kind: expand.String, Str: e.flags()}
	}
	if e.base == nil {
		return expand.Variable{}
	}
	return e.base.Get(name)
}

func (e *goshShellEnviron) Each(f func(name string, vr expand.Variable) bool) {
	if e.base == nil {
		return
	}
	e.base.Each(f)
}

type goshShellOptionProvider struct {
	runner        *interp.Runner
	interactive   bool
	readFromStdin bool
}

func (p *goshShellOptionProvider) Flags() string {
	if p == nil || p.runner == nil {
		return ""
	}
	opts := goshRunnerOpts(p.runner)
	var b strings.Builder
	b.WriteByte('h')
	if p.interactive {
		b.WriteByte('i')
		b.WriteByte('m')
		b.WriteByte('B')
		b.WriteByte('H')
		b.WriteByte('s')
	} else {
		b.WriteByte('B')
		if p.readFromStdin {
			b.WriteByte('s')
		}
	}
	// shell option mapping based on interp.shellOptsTable order
	// (allexport, errexit, noexec, noglob, nounset, xtrace).
	for _, opt := range []struct {
		index int
		flag  byte
	}{
		{0, 'a'},
		{1, 'e'},
		{2, 'n'},
		{3, 'f'},
		{4, 'u'},
		{5, 'x'},
	} {
		if opt.index < len(opts) && opts[opt.index] {
			b.WriteByte(opt.flag)
		}
	}
	return b.String()
}

func goshRunnerOpts(r *interp.Runner) []bool {
	if r == nil {
		return nil
	}
	val := reflect.ValueOf(r).Elem().FieldByName("opts")
	if !val.IsValid() || !val.CanAddr() || val.Len() == 0 {
		return nil
	}
	ptr := unsafe.Pointer(val.UnsafeAddr())
	return unsafe.Slice((*bool)(ptr), val.Len())
}

func goshBindExecMiddleware(mgr *goshKeyBindingManager) func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) > 0 && args[0] == "bind" {
				return mgr.handleBind(args[1:])
			}
			return next(ctx, args)
		}
	}
}

type goshKeyBindingManager struct {
	mu      sync.RWMutex
	entries map[string]*goKeyBindingEntry
}

type goKeyBindingEntry struct {
	seq    []byte
	action rune
}

func (m *goshKeyBindingManager) handleBind(args []string) error {
	keySpec, actionSpec, err := goshParseBindArgs(args)
	if err != nil {
		return err
	}
	seq, err := goshParseKeySequence(keySpec)
	if err != nil {
		return err
	}
	if len(seq) == 0 {
		return fmt.Errorf("bind: empty key sequence")
	}
	actionRune, ok := goshLookupBindAction(actionSpec)
	if !ok {
		return fmt.Errorf("bind: unsupported action %q", actionSpec)
	}
	m.store(seq, actionRune)
	return nil
}

func (m *goshKeyBindingManager) store(seq []byte, action rune) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(seq)
	entry := &goKeyBindingEntry{seq: append([]byte(nil), seq...), action: action}
	m.entries[key] = entry
}

func (m *goshKeyBindingManager) match(buf []byte) (rune, int, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.entries) == 0 {
		return 0, 0, false
	}
	needMore := false
	var matched rune
	var matchedLen int
	for _, entry := range m.entries {
		seq := entry.seq
		switch {
		case len(buf) >= len(seq) && bytes.Equal(buf[:len(seq)], seq):
			if len(seq) > matchedLen {
				matched = entry.action
				matchedLen = len(seq)
			}
		case len(buf) < len(seq) && bytes.Equal(seq[:len(buf)], buf):
			needMore = true
		}
	}
	if matchedLen > 0 {
		return matched, matchedLen, false
	}
	return 0, 0, needMore
}

func goshParseBindArgs(args []string) (string, string, error) {
	if len(args) == 0 {
		return "", "", fmt.Errorf("bind: missing arguments")
	}
	if len(args) == 1 {
		parts := strings.SplitN(args[0], ":", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("bind: invalid format, expected key: action")
		}
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
	}
	key := args[0]
	if strings.HasSuffix(key, ":") {
		key = key[:len(key)-1]
	}
	action := strings.Join(args[1:], " ")
	return strings.TrimSpace(key), strings.TrimSpace(action), nil
}

func goshParseKeySequence(spec string) ([]byte, error) {
	s := goshTrimOuterQuotes(strings.TrimSpace(spec))
	var out []byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch != '\\' {
			out = append(out, ch)
			continue
		}
		i++
		if i >= len(s) {
			return nil, fmt.Errorf("bind: trailing escape in %q", spec)
		}
		switch s[i] {
		case 'e', 'E':
			out = append(out, 0x1b)
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '\\':
			out = append(out, '\\')
		case '\'':
			out = append(out, '\'')
		case '"':
			out = append(out, '"')
		case 'x', 'X':
			if i+2 >= len(s) {
				return nil, fmt.Errorf("bind: incomplete hex escape in %q", spec)
			}
			val, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, fmt.Errorf("bind: invalid hex escape in %q", spec)
			}
			out = append(out, byte(val))
			i += 2
		case 'C', 'c':
			if i+1 >= len(s) || s[i+1] != '-' {
				out = append(out, s[i])
				continue
			}
			i += 2
			if i >= len(s) {
				return nil, fmt.Errorf("bind: malformed control sequence in %q", spec)
			}
			if s[i] == '?' {
				out = append(out, 0x7f)
			} else {
				out = append(out, s[i]&0x1f)
			}
		case 'M', 'm':
			if i+1 >= len(s) || s[i+1] != '-' {
				out = append(out, s[i])
				continue
			}
			i += 2
			if i >= len(s) {
				return nil, fmt.Errorf("bind: malformed meta sequence in %q", spec)
			}
			out = append(out, 0x80|s[i])
		default:
			out = append(out, s[i])
		}
	}
	return out, nil
}

func goshLookupBindAction(action string) (rune, bool) {
	switch strings.ToLower(goshTrimOuterQuotes(strings.TrimSpace(action))) {
	case "beginning-of-line", "start-of-line", "home":
		return readline.CharLineStart, true
	case "end-of-line", "cursor-end", "end":
		return readline.CharLineEnd, true
	case "previous-screen":
		return readline.CharPrev, true
	case "next-screen":
		return readline.CharNext, true
	default:
		return 0, false
	}
}

func goshTrimOuterQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

type goshKeyBindingInput struct {
	src io.Reader
	mgr *goshKeyBindingManager
	buf []byte
	out []byte
	tmp [64]byte
}

func (r *goshKeyBindingInput) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		n, err := r.src.Read(r.tmp[:])
		if n > 0 {
			r.buf = append(r.buf, r.tmp[:n]...)
			r.processBuffer()
		}
		if len(r.out) > 0 {
			break
		}
		if err != nil {
			if err == io.EOF {
				if len(r.buf) > 0 {
					r.out = append(r.out, r.buf...)
					r.buf = nil
					continue
				}
				if len(r.out) > 0 {
					break
				}
			}
			return 0, err
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *goshKeyBindingInput) processBuffer() {
	for len(r.buf) > 0 {
		action, size, needMore := r.mgr.match(r.buf)
		if size > 0 {
			r.out = append(r.out, byte(action))
			r.buf = r.buf[size:]
			continue
		}
		if needMore {
			return
		}
		r.out = append(r.out, r.buf[0])
		r.buf = r.buf[1:]
	}
}

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
	escaped := make([]string, len(options))
	for i, option := range options {
		escaped[i] = goshEscapeCompletion(option)
	}
	prefixLen := utf8.RuneCountInString(ctx.prefix)
	common := goshLongestCommonPrefix(escaped)
	commonRunes := []rune(common)
	addition := []rune{}
	if len(commonRunes) > prefixLen {
		addition = append(addition, commonRunes[prefixLen:]...)
	}
	if len(options) == 1 && !strings.HasSuffix(options[0], string(os.PathSeparator)) {
		addition = append(addition, ' ')
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
}

func (c *goshAutoCompleter) completionContext(line []rune, pos int) goshCompletionContext {
	if pos < 0 {
		pos = 0
	}
	if pos > len(line) {
		pos = len(line)
	}
	start := pos
	for start > 0 {
		r := line[start-1]
		if goshIsCompletionBreak(r) {
			break
		}
		start--
	}
	prefixRunes := line[start:pos]
	isCommand := c.isCommandPosition(line, start)
	cmd := c.resolveCommand(line, start)
	return goshCompletionContext{prefix: string(prefixRunes), isCommand: isCommand, command: cmd}
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
	funcStamp := c.functionStamp()
	home := c.userHome()
	commands := c.commandIndex(path, funcStamp, home)
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

func (c *goshAutoCompleter) commandIndex(path, funcStamp, home string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if path == c.cachedPath && funcStamp == c.cachedFuncStamp && home == c.cachedHome && len(c.cachedCommands) > 0 {
		return c.cachedCommands
	}
	cmds := c.buildCommandIndexLocked(path, home)
	c.cachedPath = path
	c.cachedFuncStamp = funcStamp
	c.cachedHome = home
	c.cachedCommands = cmds
	return cmds
}

func (c *goshAutoCompleter) buildCommandIndexLocked(path, home string) []string {
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
				add(entry.Name())
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
		if dirsOnly && !entry.IsDir() {
			continue
		}
		candidate := dirPart + name
		if entry.IsDir() {
			candidate += string(os.PathSeparator)
		}
		matches = append(matches, candidate)
	}
	slices.Sort(matches)
	return matches
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
	if val == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range val {
		switch r {
		case ' ', '\t', '\n', '\\', '"', '\'', '`', '$', '&', '|', ';', '<', '>', '(', ')', '{', '}', '[', ']', '!', '?', '*', '~', '^', '#', '%', '=', ':', ',', '+':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
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
