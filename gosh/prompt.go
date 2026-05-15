package gosh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func goshDefaultPrompt(version string) string {
	symbol := "$"
	if os.Geteuid() == 0 {
		symbol = "#"
	}
	return "sh-" + goshShortVersion(version) + symbol + " "
}

func goshShortVersion(version string) string {
	if len(version) > 3 {
		return version[:3]
	}
	if version == "" {
		return "0.0"
	}
	return version
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
