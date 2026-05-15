package gosh

import (
	"reflect"
	"strings"
	"sync"
	"unsafe"

	"github.com/chzyer/readline"
)

type goshHistorySearch struct {
	history *goshHistory
	rl      *readline.Instance

	mu           sync.Mutex
	line         []rune
	pos          int
	searchActive bool
	searchPrefix string
	searchPos    int
	searchEmpty  bool
	searchIndex  int
	historySize  int
	setBuffer    func(*readline.Instance, []rune, int) bool
}

func (h *goshHistorySearch) Attach(rl *readline.Instance) {
	h.mu.Lock()
	h.rl = rl
	h.mu.Unlock()
}

func (h *goshHistorySearch) Search(action rune) bool {
	if h.applySearch(action) {
		return true
	}
	h.emitBell()
	return true
}

func (h *goshHistorySearch) OnChange(line []rune, pos int, _ rune) (newLine []rune, newPos int, ok bool) {
	h.mu.Lock()
	h.line = append(h.line[:0], line...)
	if pos < 0 {
		pos = 0
	} else if pos > len(line) {
		pos = len(line)
	}
	h.pos = pos
	h.resetSearchLocked()
	h.mu.Unlock()
	return nil, 0, false
}

func (h *goshHistorySearch) resetSearch() {
	h.mu.Lock()
	h.resetSearchLocked()
	h.mu.Unlock()
}

func (h *goshHistorySearch) resetSearchLocked() {
	h.searchActive = false
	h.searchPrefix = ""
	h.searchPos = 0
	h.searchEmpty = false
	h.historySize = 0
	h.searchIndex = -1
}

func (h *goshHistorySearch) applySearch(action rune) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.history == nil || h.rl == nil && h.setBuffer == nil {
		return false
	}
	entries := h.history.Entries()
	if !h.searchActive || len(entries) != h.historySize {
		h.searchPrefix = h.currentPrefixLocked()
		h.searchPos = h.pos
		h.searchEmpty = h.searchPos == 0 && h.searchPrefix == "" && len(h.line) == 0
		h.searchActive = true
		h.historySize = len(entries)
		if action == goshKeyActionHistorySearchBackward {
			h.searchIndex = len(entries)
		} else {
			h.searchIndex = -1
		}
	}
	if len(entries) == 0 {
		return false
	}
	start := h.searchIndex
	var candidate string
	if action == goshKeyActionHistorySearchBackward {
		for idx := start - 1; idx >= 0; idx-- {
			if strings.HasPrefix(entries[idx], h.searchPrefix) {
				candidate = entries[idx]
				h.searchIndex = idx
				break
			}
		}
	} else {
		for idx := start + 1; idx < len(entries); idx++ {
			if strings.HasPrefix(entries[idx], h.searchPrefix) {
				candidate = entries[idx]
				h.searchIndex = idx
				break
			}
		}
	}
	if candidate == "" {
		return false
	}
	runes := []rune(candidate)
	pos := h.searchPos
	if h.searchEmpty {
		pos = len(runes)
	} else if pos < 0 {
		pos = 0
	} else if pos > len(runes) {
		pos = len(runes)
	}
	if !h.setReadlineBuffer(runes, pos) {
		return false
	}
	h.line = append(h.line[:0], runes...)
	h.pos = pos
	return true
}

func (h *goshHistorySearch) setReadlineBuffer(line []rune, pos int) bool {
	if h.setBuffer != nil {
		return h.setBuffer(h.rl, line, pos)
	}
	return goshSetReadlineBuffer(h.rl, line, pos)
}

func goshSetReadlineBuffer(rl *readline.Instance, line []rune, pos int) bool {
	if rl == nil || rl.Operation == nil {
		return false
	}
	if pos < 0 {
		pos = 0
	} else if pos > len(line) {
		pos = len(line)
	}
	op := reflect.ValueOf(rl.Operation)
	if !op.IsValid() || op.Kind() != reflect.Pointer || op.IsNil() {
		return false
	}
	bufField := op.Elem().FieldByName("buf")
	if !bufField.IsValid() || !bufField.CanAddr() || bufField.Kind() != reflect.Pointer || bufField.IsNil() {
		return false
	}
	buf, ok := reflect.NewAt(bufField.Type(), unsafe.Pointer(bufField.UnsafeAddr())).Elem().Interface().(*readline.RuneBuffer)
	if !ok || buf == nil {
		return false
	}
	buf.SetWithIdx(pos, append([]rune(nil), line...))
	return true
}

func (h *goshHistorySearch) currentPrefixLocked() string {
	line := h.line
	pos := h.pos
	if pos < 0 {
		pos = 0
	} else if pos > len(line) {
		pos = len(line)
	}
	return string(line[:pos])
}

func (h *goshHistorySearch) emitBell() {
	h.mu.Lock()
	rl := h.rl
	h.mu.Unlock()
	if rl == nil {
		return
	}
	if w := rl.Stdout(); w != nil {
		_, _ = w.Write([]byte{0x07})
	}
}
