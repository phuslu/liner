package main

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func gosh(ctx context.Context, isatty bool, stdin io.Reader, stdout, stderr io.Writer) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

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
	runner, err := interp.New(
		interp.Interactive(true),
		interp.StdIO(stdin, stdout, stderr),
	)
	if err != nil {
		return err
	}

	// Source the init file specified by GOSH_ENV, if set.
	if filename := os.Getenv("GOSH_ENV"); filename != "" {
		if file, err := os.Open(filename); err == nil {
			prog, err := parser.Parse(file, filename)
			if err != nil {
				fmt.Fprintln(stderr, "failed to parse", filename, ":", err)
			} else {
				if err := runner.Run(ctx, prog); err != nil {
					fmt.Fprintln(stderr, "failed to run", filename, ":", err)
				}
			}
			file.Close()
		} else {
			fmt.Fprintln(stderr, "failed to open", filename, ":", err)
		}
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

	histFile := ""
	if home, err := os.UserHomeDir(); err == nil {
		histFile = home + "/.gosh_history"
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          currentPrompt.prompt,
		HistoryFile:     histFile,
		HistoryLimit:    1000,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		Stdout:          cmp.Or(stdout.(*os.File), os.Stdout),
		Stderr:          cmp.Or(stderr.(*os.File), os.Stderr),
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
	defer rl.Close()
	printPromptPrefix(rl.Stdout(), currentPrompt.prefix)
	nextPrefix := ""
	setPrompt := func(parts promptParts) {
		rl.SetPrompt(parts.prompt)
		nextPrefix = parts.prefix
	}
	flushPrefix := func() {
		if nextPrefix == "" {
			return
		}
		printPromptPrefix(rl.Stdout(), nextPrefix)
		nextPrefix = ""
	}

	// goshReader wraps readline so parser.Interactive can consume it as an
	// io.Reader. Each call to Read invokes Readline() to fetch one line.
	// Ctrl-C (ErrInterrupt) injects a newline to abandon the current
	// incomplete statement. Ctrl-D / EOF returns io.EOF to end the session.
	rdr := &goshReader{rl: rl}

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

		// Restore the main prompt, updating it in case the effective UID
		// changed (e.g. via su).
		setPrompt(goshPromptString(ctx, runner, stdin, stderr, "PS1", goshDefaultPrompt(), promptSeq))
		promptSeq++

		for _, stmt := range stmts {
			if err := runner.Run(ctx, stmt); err != nil {
				fmt.Fprintln(rl.Stdout(), err.Error())
			}
			if runner.Exited() {
				return false
			}
		}
		flushPrefix()
		return true
	})
}

// goshReader adapts *readline.Instance to the io.Reader interface expected by
// parser.Interactive. The parser calls Read whenever it needs more input.
type goshReader struct {
	rl  *readline.Instance
	buf []byte // leftover bytes from the previous Readline call
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

	data := []byte(line + "\n")
	n := copy(p, data)
	if n < len(data) {
		r.buf = data[n:] // stash the remainder for the next Read call
	}
	return n, nil
}

func goshDefaultPrompt() string {
	if os.Geteuid() == 0 {
		return "# "
	}
	return "$ "
}

func goshPromptString(ctx context.Context, runner *interp.Runner, stdin io.Reader, stderr io.Writer, name, fallback string, seq int) promptParts {
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
		return promptParts{prompt: fallback}
	}
	return splitPromptLines(newPromptRenderer(val, state).render())
}

type promptParts struct {
	prefix string
	prompt string
}

func splitPromptLines(val string) promptParts {
	idx := strings.LastIndexByte(val, '\n')
	if idx < 0 {
		return promptParts{prompt: val}
	}
	return promptParts{
		prefix: val[:idx+1],
		prompt: val[idx+1:],
	}
}

func printPromptPrefix(w io.Writer, prefix string) {
	if prefix == "" || w == nil {
		return
	}
	fmt.Fprint(w, prefix)
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

func newPromptRenderer(src string, state *goshPromptState) *goshPromptRenderer {
	return &goshPromptRenderer{src: src, state: state}
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
				b.WriteString(newPromptRenderer(inner, r.state).render())
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
	prog, err := syntax.NewParser().Parse(strings.NewReader(script), "")
	if err != nil {
		return "", err
	}
	sub := p.runner.Subshell()
	var buf bytes.Buffer
	interp.StdIO(p.stdin, &buf, p.stderr)(sub)
	if err := sub.Run(p.ctx, prog); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

func (p *goshPromptState) escapeDouble(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}
