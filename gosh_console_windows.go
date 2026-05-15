//go:build windows

package main

import (
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

var (
	goshConsoleMu                       sync.Mutex
	goshConsoleKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	goshProcGetConsoleScreenBufferInfo  = goshConsoleKernel32.NewProc("GetConsoleScreenBufferInfo")
	goshProcSetConsoleCursorPosition    = goshConsoleKernel32.NewProc("SetConsoleCursorPosition")
	goshProcWriteConsoleW               = goshConsoleKernel32.NewProc("WriteConsoleW")
	goshProcFillConsoleOutputCharacterW = goshConsoleKernel32.NewProc("FillConsoleOutputCharacterW")
	goshProcFillConsoleOutputAttribute  = goshConsoleKernel32.NewProc("FillConsoleOutputAttribute")
	goshProcSetConsoleTextAttribute     = goshConsoleKernel32.NewProc("SetConsoleTextAttribute")
	goshProcGetConsoleCursorInfo        = goshConsoleKernel32.NewProc("GetConsoleCursorInfo")
	goshProcSetConsoleCursorInfo        = goshConsoleKernel32.NewProc("SetConsoleCursorInfo")
)

type goshConsoleCoord struct {
	X int16
	Y int16
}

type goshConsoleSmallRect struct {
	Left   int16
	Top    int16
	Right  int16
	Bottom int16
}

type goshConsoleScreenBufferInfo struct {
	Size              goshConsoleCoord
	CursorPosition    goshConsoleCoord
	Attributes        uint16
	Window            goshConsoleSmallRect
	MaximumWindowSize goshConsoleCoord
}

type goshConsoleCursorInfo struct {
	Size    uint32
	Visible int32
}

type goshConsoleWriter struct {
	handle   syscall.Handle
	attr     uint16
	baseAttr uint16
	state    byte
	seq      []byte
	text     []byte
}

func goshInteractiveUIWriter(stderr io.Writer) io.Writer {
	if stderr == nil {
		return io.Discard
	}
	return goshNewConsoleWriter(stderr)
}

func goshNewConsoleWriter(out io.Writer) io.Writer {
	file, ok := out.(*os.File)
	if !ok {
		return out
	}
	handle := syscall.Handle(file.Fd())
	var mode uint32
	if err := syscall.GetConsoleMode(handle, &mode); err != nil {
		return out
	}
	info, err := getConsoleScreenBufferInfo(handle)
	if err != nil {
		return out
	}
	return &goshConsoleWriter{
		handle:   handle,
		attr:     info.Attributes,
		baseAttr: info.Attributes,
	}
}

func (w *goshConsoleWriter) Write(p []byte) (int, error) {
	goshConsoleMu.Lock()
	defer goshConsoleMu.Unlock()

	cursor, restoreCursor := w.hideCursor(bytesContainConsoleControl(p))
	if restoreCursor {
		defer w.setCursorInfo(cursor)
	}

	for _, c := range p {
		if err := w.writeByte(c); err != nil {
			return 0, err
		}
	}
	if err := w.flushText(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func bytesContainConsoleControl(p []byte) bool {
	for _, c := range p {
		switch c {
		case '\x1b', '\r', '\n', '\b':
			return true
		}
	}
	return false
}

func (w *goshConsoleWriter) writeByte(c byte) error {
	const (
		goshConsoleStateText = iota
		goshConsoleStateEsc
		goshConsoleStateCSI
		goshConsoleStateOSC
		goshConsoleStateOSCEsc
	)

	switch w.state {
	case goshConsoleStateEsc:
		switch c {
		case '[':
			w.seq = w.seq[:0]
			w.state = goshConsoleStateCSI
		case ']':
			w.seq = w.seq[:0]
			w.state = goshConsoleStateOSC
		default:
			w.state = goshConsoleStateText
		}
		return nil
	case goshConsoleStateCSI:
		if c >= 0x40 && c <= 0x7e {
			err := w.handleCSI(c, string(w.seq))
			w.seq = w.seq[:0]
			w.state = goshConsoleStateText
			return err
		}
		w.seq = append(w.seq, c)
		return nil
	case goshConsoleStateOSC:
		switch c {
		case '\a':
			w.seq = w.seq[:0]
			w.state = goshConsoleStateText
		case '\x1b':
			w.state = goshConsoleStateOSCEsc
		default:
			w.seq = append(w.seq, c)
		}
		return nil
	case goshConsoleStateOSCEsc:
		if c == '\\' {
			w.seq = w.seq[:0]
			w.state = goshConsoleStateText
			return nil
		}
		w.state = goshConsoleStateOSC
		w.seq = append(w.seq, '\x1b', c)
		return nil
	}

	switch c {
	case '\x1b':
		if err := w.flushText(); err != nil {
			return err
		}
		w.state = goshConsoleStateEsc
	case '\r':
		if err := w.flushText(); err != nil {
			return err
		}
		return w.carriageReturn()
	case '\n':
		if err := w.flushText(); err != nil {
			return err
		}
		return w.writeConsoleString("\r\n")
	case '\b':
		if err := w.flushText(); err != nil {
			return err
		}
		return w.backspace()
	default:
		w.text = append(w.text, c)
	}
	return nil
}

func (w *goshConsoleWriter) flushText() error {
	if len(w.text) == 0 {
		return nil
	}
	n := validUTF8Prefix(w.text)
	if n == 0 {
		return nil
	}
	if err := w.writeConsoleString(string(w.text[:n])); err != nil {
		return err
	}
	copy(w.text, w.text[n:])
	w.text = w.text[:len(w.text)-n]
	return nil
}

func validUTF8Prefix(p []byte) int {
	var n int
	for n < len(p) {
		r, size := utf8.DecodeRune(p[n:])
		if r == utf8.RuneError && size == 1 && !utf8.FullRune(p[n:]) {
			break
		}
		n += size
	}
	return n
}

func (w *goshConsoleWriter) writeConsoleString(s string) error {
	if s == "" {
		return nil
	}
	u16 := utf16.Encode([]rune(s))
	for len(u16) != 0 {
		n := len(u16)
		if n > 32*1024 {
			n = 32 * 1024
		}
		var written uint32
		if err := writeConsole(w.handle, &u16[0], uint32(n), &written); err != nil {
			return err
		}
		u16 = u16[n:]
	}
	return nil
}

func (w *goshConsoleWriter) handleCSI(final byte, seq string) error {
	switch final {
	case 'A':
		return w.moveCursor(0, -csiFirst(seq, 1))
	case 'B':
		return w.moveCursor(0, csiFirst(seq, 1))
	case 'C':
		return w.moveCursor(csiFirst(seq, 1), 0)
	case 'D':
		return w.moveCursor(-csiFirst(seq, 1), 0)
	case 'G':
		return w.setCursorColumn(csiFirst(seq, 1) - 1)
	case 'H', 'f':
		return w.setCursorPosition(seq)
	case 'J':
		return w.eraseDisplay(csiFirst(seq, 0))
	case 'K':
		return w.eraseLine(csiFirst(seq, 0))
	case 'm':
		return w.setSGR(seq)
	case 'h', 'l':
		if seq == "?25" {
			return w.showCursor(final == 'h')
		}
	}
	return nil
}

func csiFirst(seq string, def int) int {
	parts := csiParts(seq)
	if len(parts) == 0 || parts[0] == "" {
		return def
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n < 1 {
		return def
	}
	return n
}

func csiParts(seq string) []string {
	if seq == "" {
		return nil
	}
	seq = strings.TrimPrefix(seq, "?")
	return strings.Split(seq, ";")
}

func (w *goshConsoleWriter) screenBufferInfo() (goshConsoleScreenBufferInfo, error) {
	return getConsoleScreenBufferInfo(w.handle)
}

func (w *goshConsoleWriter) setCursor(pos goshConsoleCoord) error {
	info, err := w.screenBufferInfo()
	if err != nil {
		return err
	}
	if pos.X < 0 {
		pos.X = 0
	} else if info.Size.X > 0 && pos.X >= info.Size.X {
		pos.X = info.Size.X - 1
	}
	if pos.Y < 0 {
		pos.Y = 0
	} else if info.Size.Y > 0 && pos.Y >= info.Size.Y {
		pos.Y = info.Size.Y - 1
	}
	return setConsoleCursorPosition(w.handle, pos)
}

func (w *goshConsoleWriter) moveCursor(dx, dy int) error {
	info, err := w.screenBufferInfo()
	if err != nil {
		return err
	}
	return w.setCursor(goshConsoleCoord{
		X: info.CursorPosition.X + int16(dx),
		Y: info.CursorPosition.Y + int16(dy),
	})
}

func (w *goshConsoleWriter) setCursorColumn(x int) error {
	info, err := w.screenBufferInfo()
	if err != nil {
		return err
	}
	return w.setCursor(goshConsoleCoord{X: int16(x), Y: info.CursorPosition.Y})
}

func (w *goshConsoleWriter) setCursorPosition(seq string) error {
	parts := csiParts(seq)
	row, col := 1, 1
	if len(parts) > 0 && parts[0] != "" {
		if n, err := strconv.Atoi(parts[0]); err == nil && n > 0 {
			row = n
		}
	}
	if len(parts) > 1 && parts[1] != "" {
		if n, err := strconv.Atoi(parts[1]); err == nil && n > 0 {
			col = n
		}
	}
	return w.setCursor(goshConsoleCoord{X: int16(col - 1), Y: int16(row - 1)})
}

func (w *goshConsoleWriter) carriageReturn() error {
	info, err := w.screenBufferInfo()
	if err != nil {
		return err
	}
	return w.setCursor(goshConsoleCoord{X: 0, Y: info.CursorPosition.Y})
}

func (w *goshConsoleWriter) backspace() error {
	info, err := w.screenBufferInfo()
	if err != nil {
		return err
	}
	pos := info.CursorPosition
	if pos.X > 0 {
		pos.X--
	} else if pos.Y > 0 {
		pos.Y--
		pos.X = info.Size.X - 1
	}
	return w.setCursor(pos)
}

func (w *goshConsoleWriter) eraseDisplay(mode int) error {
	info, err := w.screenBufferInfo()
	if err != nil {
		return err
	}
	switch mode {
	case 2:
		cells := uint32(info.Size.X) * uint32(info.Size.Y)
		pos := goshConsoleCoord{}
		if err := w.fill(pos, cells); err != nil {
			return err
		}
		return w.setCursor(pos)
	case 1:
		cells := uint32(info.CursorPosition.Y)*uint32(info.Size.X) + uint32(info.CursorPosition.X) + 1
		return w.fill(goshConsoleCoord{}, cells)
	default:
		cells := uint32(info.Size.Y-info.CursorPosition.Y-1)*uint32(info.Size.X) + uint32(info.Size.X-info.CursorPosition.X)
		return w.fill(info.CursorPosition, cells)
	}
}

func (w *goshConsoleWriter) eraseLine(mode int) error {
	info, err := w.screenBufferInfo()
	if err != nil {
		return err
	}
	pos := info.CursorPosition
	var start goshConsoleCoord
	var cells uint32
	switch mode {
	case 1:
		start = goshConsoleCoord{Y: pos.Y}
		cells = uint32(pos.X) + 1
	case 2:
		start = goshConsoleCoord{Y: pos.Y}
		cells = uint32(info.Size.X)
	default:
		start = pos
		cells = uint32(info.Size.X - pos.X)
	}
	if err := w.fill(start, cells); err != nil {
		return err
	}
	return w.setCursor(pos)
}

func (w *goshConsoleWriter) fill(pos goshConsoleCoord, cells uint32) error {
	if cells == 0 {
		return nil
	}
	var written uint32
	if err := fillConsoleOutputCharacter(w.handle, ' ', cells, pos, &written); err != nil {
		return err
	}
	return fillConsoleOutputAttribute(w.handle, w.attr, cells, pos, &written)
}

func (w *goshConsoleWriter) setSGR(seq string) error {
	parts := csiParts(seq)
	if len(parts) == 0 {
		parts = []string{"0"}
	}
	for _, part := range parts {
		if part == "" {
			part = "0"
		}
		code, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		w.applySGR(code)
	}
	return setConsoleTextAttribute(w.handle, w.attr)
}

func (w *goshConsoleWriter) applySGR(code int) {
	const (
		fgMask     = uint16(0x000f)
		bgMask     = uint16(0x00f0)
		underscore = uint16(0x8000)
	)
	switch {
	case code == 0:
		w.attr = w.baseAttr
	case code == 1:
		w.attr |= 0x0008
	case code == 4:
		w.attr |= underscore
	case code == 22:
		w.attr &^= 0x0008
	case code == 24:
		w.attr &^= underscore
	case code == 39:
		w.attr = (w.attr &^ fgMask) | (w.baseAttr & fgMask)
	case code == 49:
		w.attr = (w.attr &^ bgMask) | (w.baseAttr & bgMask)
	case code >= 30 && code <= 37:
		w.attr = (w.attr &^ fgMask) | consoleColor(code-30, false)
	case code >= 90 && code <= 97:
		w.attr = (w.attr &^ fgMask) | consoleColor(code-90, true)
	case code >= 40 && code <= 47:
		w.attr = (w.attr &^ bgMask) | (consoleColor(code-40, false) << 4)
	case code >= 100 && code <= 107:
		w.attr = (w.attr &^ bgMask) | (consoleColor(code-100, true) << 4)
	}
}

func consoleColor(code int, bright bool) uint16 {
	colors := [...]uint16{
		0,
		0x0004,
		0x0002,
		0x0006,
		0x0001,
		0x0005,
		0x0003,
		0x0007,
	}
	color := colors[code&7]
	if bright {
		color |= 0x0008
	}
	return color
}

func (w *goshConsoleWriter) hideCursor(ok bool) (goshConsoleCursorInfo, bool) {
	if !ok {
		return goshConsoleCursorInfo{}, false
	}
	info, err := getConsoleCursorInfo(w.handle)
	if err != nil || info.Visible == 0 {
		return info, false
	}
	next := info
	next.Visible = 0
	if err := w.setCursorInfo(next); err != nil {
		return info, false
	}
	return info, true
}

func (w *goshConsoleWriter) showCursor(visible bool) error {
	info, err := getConsoleCursorInfo(w.handle)
	if err != nil {
		return err
	}
	if visible {
		info.Visible = 1
	} else {
		info.Visible = 0
	}
	return w.setCursorInfo(info)
}

func (w *goshConsoleWriter) setCursorInfo(info goshConsoleCursorInfo) error {
	r1, _, e1 := goshProcSetConsoleCursorInfo.Call(
		uintptr(w.handle),
		uintptr(unsafe.Pointer(&info)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func getConsoleScreenBufferInfo(handle syscall.Handle) (goshConsoleScreenBufferInfo, error) {
	var info goshConsoleScreenBufferInfo
	r1, _, e1 := goshProcGetConsoleScreenBufferInfo.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&info)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return info, e1
		}
		return info, syscall.EINVAL
	}
	return info, nil
}

func getConsoleCursorInfo(handle syscall.Handle) (goshConsoleCursorInfo, error) {
	var info goshConsoleCursorInfo
	r1, _, e1 := goshProcGetConsoleCursorInfo.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&info)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return info, e1
		}
		return info, syscall.EINVAL
	}
	return info, nil
}

func setConsoleCursorPosition(handle syscall.Handle, pos goshConsoleCoord) error {
	r1, _, e1 := goshProcSetConsoleCursorPosition.Call(uintptr(handle), pos.pack())
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func setConsoleTextAttribute(handle syscall.Handle, attr uint16) error {
	r1, _, e1 := goshProcSetConsoleTextAttribute.Call(uintptr(handle), uintptr(attr))
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func writeConsole(handle syscall.Handle, buf *uint16, towrite uint32, written *uint32) error {
	r1, _, e1 := goshProcWriteConsoleW.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(buf)),
		uintptr(towrite),
		uintptr(unsafe.Pointer(written)),
		0,
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func fillConsoleOutputCharacter(handle syscall.Handle, ch uint16, cells uint32, pos goshConsoleCoord, written *uint32) error {
	r1, _, e1 := goshProcFillConsoleOutputCharacterW.Call(
		uintptr(handle),
		uintptr(ch),
		uintptr(cells),
		pos.pack(),
		uintptr(unsafe.Pointer(written)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func fillConsoleOutputAttribute(handle syscall.Handle, attr uint16, cells uint32, pos goshConsoleCoord, written *uint32) error {
	r1, _, e1 := goshProcFillConsoleOutputAttribute.Call(
		uintptr(handle),
		uintptr(attr),
		uintptr(cells),
		pos.pack(),
		uintptr(unsafe.Pointer(written)),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func (c goshConsoleCoord) pack() uintptr {
	return uintptr(uint32(uint16(c.X)) | uint32(uint16(c.Y))<<16)
}
