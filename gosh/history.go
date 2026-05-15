package gosh

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"mvdan.cc/sh/v3/interp"
)

type goshHistory struct {
	limit   int
	control goshHistoryControl
	file    string
	mu      sync.Mutex
	entries []string
}

type goshHistoryControl struct {
	ignoreDups  bool
	ignoreSpace bool
}

func goshResolveHistoryLimit() int {
	val, _ := os.LookupEnv("HISTSIZE")
	if n := goshParseHistoryLimit(val); n > 0 {
		return n
	}
	return 1000
}

func goshResolveShellHistoryLimit(runner *interp.Runner) int {
	if val, ok := goshRunnerStringVar(runner, "HISTSIZE"); ok {
		if n := goshParseHistoryLimit(val); n > 0 {
			return n
		}
	}
	return goshResolveHistoryLimit()
}

func goshParseHistoryLimit(val string) int {
	n, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func goshResolveShellHistoryControl(runner *interp.Runner) goshHistoryControl {
	if val, ok := goshRunnerStringVar(runner, "HISTCONTROL"); ok {
		return goshParseHistoryControl(val)
	}
	return goshParseHistoryControl(os.Getenv("HISTCONTROL"))
}

func goshParseHistoryControl(val string) goshHistoryControl {
	var control goshHistoryControl
	for _, part := range strings.FieldsFunc(val, func(r rune) bool {
		return r == ':' || r == ',' || unicode.IsSpace(r)
	}) {
		switch part {
		case "ignoredups":
			control.ignoreDups = true
		case "ignorespace":
			control.ignoreSpace = true
		case "ignoreboth":
			control.ignoreDups = true
			control.ignoreSpace = true
		}
	}
	return control
}

func goshResolveShellHistoryFile(runner *interp.Runner) string {
	histFile, ok := goshRunnerStringVar(runner, "HISTFILE")
	if !ok {
		histFile, ok = os.LookupEnv("HISTFILE")
	}
	if !ok || histFile == os.DevNull || histFile == "/dev/null" {
		return ""
	}
	return histFile
}

func goshRunnerStringVar(runner *interp.Runner, name string) (string, bool) {
	if runner != nil && runner.Vars != nil {
		if vr, ok := runner.Vars[name]; ok && vr.IsSet() {
			return vr.String(), true
		}
	}
	if runner != nil && runner.Env != nil {
		if vr := runner.Env.Get(name); vr.IsSet() {
			return vr.String(), true
		}
	}
	return "", false
}

func (h *goshHistory) LoadFile(name string) error {
	if h == nil || name == "" {
		return nil
	}
	file, err := os.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()
	return h.Load(file)
}

func (h *goshHistory) Load(r io.Reader) error {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			h.append(goshDecodeHistoryLine(line))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (h *goshHistory) Add(line string) bool {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return false
	}
	h.mu.Lock()
	if h.control.ignoreSpace && strings.HasPrefix(line, " ") {
		h.mu.Unlock()
		return false
	}
	if h.control.ignoreDups && len(h.entries) > 0 && h.entries[len(h.entries)-1] == line {
		h.mu.Unlock()
		return false
	}
	h.appendLocked(line)
	h.mu.Unlock()
	h.appendFile(line)
	return true
}

func (h *goshHistory) append(line string) {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.appendLocked(line)
}

func (h *goshHistory) appendLocked(line string) {
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

func (h *goshHistory) appendFile(line string) {
	if h == nil || h.file == "" {
		return
	}
	file, err := os.OpenFile(h.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(file, goshEncodeHistoryLine(line))
	_ = file.Close()
}

const goshHistoryEncodedPrefix = "# gosh-history-v1 "

func goshEncodeHistoryLine(line string) string {
	if strings.ContainsAny(line, "\r\n") || strings.HasPrefix(line, goshHistoryEncodedPrefix) {
		return goshHistoryEncodedPrefix + base64.StdEncoding.EncodeToString([]byte(line))
	}
	return line
}

func goshDecodeHistoryLine(line string) string {
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, goshHistoryEncodedPrefix) {
		return line
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len(goshHistoryEncodedPrefix):]))
	if err != nil {
		return line
	}
	return string(data)
}
