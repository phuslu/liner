package gosh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chzyer/readline"
)

type goshKeyBindingManager struct {
	mu      sync.RWMutex
	entries map[string]*goKeyBindingEntry
	actions map[rune]func(rune) bool
}

type goKeyBindingEntry struct {
	seq    []byte
	action rune
}

const (
	goshKeyActionHistorySearchBackward = 0x90
	goshKeyActionHistorySearchForward  = 0x91
)

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

func (m *goshKeyBindingManager) registerActionHandler(action rune, handler func(rune) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if handler == nil {
		if m.actions != nil {
			delete(m.actions, action)
		}
		return
	}
	if m.actions == nil {
		m.actions = make(map[rune]func(rune) bool)
	}
	m.actions[action] = handler
}

func (m *goshKeyBindingManager) invokeAction(action rune) bool {
	m.mu.RLock()
	handler := m.actions[action]
	m.mu.RUnlock()
	if handler == nil {
		return false
	}
	return handler(action)
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
	case "history-search-backward":
		return goshKeyActionHistorySearchBackward, true
	case "history-search-forward":
		return goshKeyActionHistorySearchForward, true
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

	needMore bool
}

const goshKeyBindingPrefixTimeout = 50 * time.Millisecond

type goshReadDeadliner interface {
	SetReadDeadline(time.Time) error
}

func (r *goshKeyBindingInput) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		var deadliner goshReadDeadliner
		deadlineSet := false
		if r.needMore && len(r.buf) > 0 {
			if d, ok := r.src.(goshReadDeadliner); ok {
				if err := d.SetReadDeadline(time.Now().Add(goshKeyBindingPrefixTimeout)); err == nil {
					deadliner = d
					deadlineSet = true
				}
			}
		}
		n, err := r.src.Read(r.tmp[:])
		if deadlineSet {
			_ = deadliner.SetReadDeadline(time.Time{})
		}
		if n > 0 {
			r.buf = append(r.buf, r.tmp[:n]...)
			r.needMore = r.processBuffer()
		}
		if len(r.out) > 0 {
			break
		}
		if err != nil {
			if goshIsReadTimeout(err) && len(r.buf) > 0 {
				r.out = append(r.out, r.buf[0])
				r.buf = r.buf[1:]
				r.needMore = r.processBuffer()
				continue
			}
			if err == io.EOF {
				if len(r.buf) > 0 {
					r.out = append(r.out, r.buf...)
					r.buf = nil
					r.needMore = false
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

func goshIsReadTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var timeout interface {
		Timeout() bool
	}
	return errors.As(err, &timeout) && timeout.Timeout()
}

func (r *goshKeyBindingInput) processBuffer() bool {
	for len(r.buf) > 0 {
		action, size, needMore := r.mgr.match(r.buf)
		if size > 0 {
			if r.mgr.invokeAction(action) {
				r.buf = r.buf[size:]
				continue
			}
			r.out = append(r.out, byte(action))
			r.buf = r.buf[size:]
			continue
		}
		if needMore {
			return true
		}
		r.out = append(r.out, r.buf[0])
		r.buf = r.buf[1:]
	}
	return false
}
