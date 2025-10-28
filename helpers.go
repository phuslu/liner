package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unsafe"

	"github.com/libp2p/go-yamux/v5"
	"github.com/phuslu/log"
	"github.com/quic-go/quic-go"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/crypto/ssh"
)

// fastrand returns a pseudorandom uint32.
//
//go:noescape
//go:linkname fastrand runtime.cheaprand
func fastrand() uint32

// fastrand returns a pseudorandom uint64.
//
//go:noescape
//go:linkname fastrand64 runtime.fastrand64
func fastrand64() uint64

// fastrandn returns a pseudorandom uint32 in [0,n).
//
//go:noescape
//go:linkname fastrandn runtime.cheaprandn
func fastrandn(x uint32) uint32

func b2s(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func s2b(s string) (b []byte) {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh := *(*reflect.StringHeader)(unsafe.Pointer(&s))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return b
}

func ptr[T any](v T) *T {
	return &v
}

func btoi[B ~bool](x B) int {
	if x {
		return 1
	}
	return 0
}

func first[T, U any](t T, _ ...U) T {
	return t
}

func must[T, U any](t T, u ...U) T {
	v := any(u[len(u)-1])
	switch v := v.(type) {
	case bool:
		if !v {
			panic(v)
		}
	case error:
		if v != nil {
			panic(v)
		}
	}
	return t
}

func filter[T any](items []T, pred func(T) bool) []T {
	var result []T
	for _, item := range items {
		if pred(item) {
			result = append(result, item)
		}
	}
	return result
}

func filtermap[T any, R any](items []T, mapper func(T) (R, bool)) []R {
	result := make([]R, 0, len(items))
	for _, item := range items {
		if v, ok := mapper(item); ok {
			result = append(result, v)
		}
	}
	return result
}

var IsLittleEndian = func() bool {
	var i uint16 = 0x1234
	return *(*byte)(unsafe.Pointer(&i)) == 0x34
}()

// AppendToLower appends the ASCII-lowercased version of string s to dst,
// and returns the resulting slice.
//
// This function performs in-place, allocation-free ASCII lowercasing.
// Only ASCII uppercase letters A–Z are converted to lowercase;
// all other bytes are copied verbatim.
//
// It is optimized for DNS domain names, which are case-insensitive and
// often arrive in mixed-case (e.g., from Google 8.8.8.8 recursion). This
// function assumes ASCII-only input and avoids Unicode handling.
//
// Example usage:
//
//	domain := b2s(AppendToLower(make([]byte, 0, 256), req.Message.Domain))
//
// Performance: If dst has sufficient capacity (as above), no heap allocations
// occur. This makes it suitable for high-performance DNS parsing pipelines.
//
// Safety: The returned []byte aliases dst. It is safe to use with b2s for
// zero-copy conversion only if the buffer is not modified afterward.
// Behavior is undefined for non-ASCII input.
func AppendToLower(dst []byte, s string) []byte {
	if len(s) == 0 {
		return dst
	}
	n := len(dst)
	dst = append(dst, s...)
	m := n + len(s) - 1

	_ = dst[m]
	for i := n; i <= m; i++ {
		c := dst[i]
		if 'A' <= c && c <= 'Z' {
			dst[i] = c + ('a' - 'A')
		}
	}

	return dst
}

/*
	  b := AppendableBytes(make([]byte, 0, 1024))
	  b = b.Str("GET ").Str(req.RequestURI).Str(" HTTP/1.1\r\n")
	  for key, values := range req.Header {
		for _, value := range values {
			b = b.Str(key).Str(": ").Str(value).Str("\r\n")
	  	}
	  }
	  b = b.Str("\r\n")
*/
type AppendableBytes []byte

func (b AppendableBytes) Str(s string) AppendableBytes {
	return append(b, s...)
}

func (b AppendableBytes) Bytes(s []byte) AppendableBytes {
	return append(b, s...)
}

func (b AppendableBytes) Byte(c byte) AppendableBytes {
	return append(b, c)
}

func (b AppendableBytes) Base64(data []byte) AppendableBytes {
	return base64.StdEncoding.AppendEncode(b, data)
}

func (b AppendableBytes) Hex(data []byte) AppendableBytes {
	return hex.AppendEncode(b, data)
}

func (b AppendableBytes) NetIPAddr(ip netip.Addr) AppendableBytes {
	return ip.AppendTo(b)
}

func (b AppendableBytes) NetIPAddrPort(addr netip.AddrPort) AppendableBytes {
	return addr.AppendTo(b)
}

func (b AppendableBytes) Uint64(i uint64, base int) AppendableBytes {
	return strconv.AppendUint(b, i, base)
}

func (b AppendableBytes) Int64(i int64, base int) AppendableBytes {
	return strconv.AppendInt(b, i, base)
}

func (b AppendableBytes) Pad(c byte, base int) AppendableBytes {
	n := (base - len(b)%base) % base
	if n == 0 {
		return b
	}
	if n <= 32 {
		b = append(b, make([]byte, 32)...)
		b = b[:len(b)+n-32]
	} else {
		b = append(b, make([]byte, n)...)
	}
	if c != 0 {
		m := len(b) - 1
		_ = b[m]
		for i := m - n + 1; i <= m; i++ {
			b[i] = c
		}
	}
	return b
}

// AppendSplitLines splits the input string by lines and appends them to the dst slice.
func AppendSplitLines(dst []string, input string) []string {
	var i int
	for {
		i = strings.IndexByte(input, '\n')
		if i > 0 {
			_ = input[i]
			if input[i-1] != '\r' {
				dst = append(dst, input[:i])
			} else {
				dst = append(dst, input[:i-1])
			}
			input = input[i+1:]
		} else if i == 0 {
			dst = append(dst, "")
			input = input[i+1:]
		} else {
			break
		}
	}

	if len(input) > 0 {
		if i = len(input) - 1; input[i] == '\r' {
			dst = append(dst, input[:i])
		} else {
			dst = append(dst, input)
		}
	}

	return dst
}

func AppendTemplate(dst []byte, template string, startTag, endTag byte, m map[string]any, stripSpace bool) []byte {
	j := 0
	for i := 0; i < len(template); i++ {
		switch template[i] {
		case startTag:
			dst = append(dst, template[j:i]...)
			j = i
		case endTag:
			v, ok := m[template[j+1:i]]
			if !ok {
				dst = append(dst, template[j:i]...)
				j = i
				continue
			}
			switch v.(type) {
			case string:
				dst = append(dst, v.(string)...)
			case []byte:
				dst = append(dst, v.([]byte)...)
			case int:
				dst = strconv.AppendInt(dst, int64(v.(int)), 10)
			case int8:
				dst = strconv.AppendInt(dst, int64(v.(int8)), 10)
			case int16:
				dst = strconv.AppendInt(dst, int64(v.(int16)), 10)
			case int32:
				dst = strconv.AppendInt(dst, int64(v.(int32)), 10)
			case int64:
				dst = strconv.AppendInt(dst, v.(int64), 10)
			case uint:
				dst = strconv.AppendUint(dst, uint64(v.(uint)), 10)
			case uint8:
				dst = strconv.AppendUint(dst, uint64(v.(uint8)), 10)
			case uint16:
				dst = strconv.AppendUint(dst, uint64(v.(uint16)), 10)
			case uint32:
				dst = strconv.AppendUint(dst, uint64(v.(uint32)), 10)
			case uint64:
				dst = strconv.AppendUint(dst, v.(uint64), 10)
			case float32:
				dst = strconv.AppendFloat(dst, float64(v.(float32)), 'f', -1, 64)
			case float64:
				dst = strconv.AppendFloat(dst, v.(float64), 'f', -1, 64)
			default:
				dst = fmt.Append(dst, v)
			}
			j = i + 1
		case '\r', '\n':
			if stripSpace {
				dst = append(dst, template[j:i]...)
				for j = i; j < len(template); j++ {
					b := template[j]
					if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
						break
					}
				}
				i = j
			}
		}
	}
	dst = append(dst, template[j:]...)
	return dst
}

// AppendReadFrom efficiently reads all data from r and appends it to dst.
//
// This function implements a memory-efficient alternative to append(dst, io.ReadAll(r)...)
// by reusing the existing capacity of dst and growing the buffer using an exponential
// doubling strategy to minimize allocations.
//
// Parameters:
//   - dst: The destination slice to append to. Can be nil, empty, or contain existing data.
//   - r:   The io.Reader to read all data from.
//
// Returns:
//   - []byte: The resulting slice containing original dst data followed by all read data.
//   - int64:  The number of bytes read from r (excluding the original length of dst).
//   - error:  Any error encountered during reading. io.EOF is not returned as an error.
//
// The function guarantees that:
//   - All existing data in dst is preserved at the beginning of the result
//   - Memory allocations are minimized through capacity reuse and doubling growth
//   - The returned byte count matches exactly what was read from the reader
//   - Behavior is consistent with standard library io.ReaderFrom interface patterns
//
// Example:
//
//	data := make([]byte, 0, 1500)
//	data, _, err = AppendReadFrom(data, conn)
func AppendReadFrom(dst []byte, r io.Reader) ([]byte, int64, error) {
	nStart := int64(len(dst))
	nMax := int64(cap(dst))
	n := nStart
	if nMax == 0 {
		nMax = 64
		dst = make([]byte, nMax)
	} else {
		dst = dst[:nMax]
	}
	for {
		if n == nMax {
			nMax *= 2
			bNew := make([]byte, nMax)
			copy(bNew, dst)
			dst = bNew
		}
		nn, err := r.Read(dst[n:])
		n += int64(nn)
		if err != nil {
			dst = dst[:n]
			n -= nStart
			if err == io.EOF {
				return dst, n, nil
			}
			return dst, n, err
		}
	}
}

var _ io.Writer = (*WritableBytes)(nil)

type WritableBytes struct {
	B []byte
}

func (w *WritableBytes) Write(b []byte) (int, error) {
	w.B = append(w.B, b...)
	return len(b), nil
}

func (w *WritableBytes) Reset() {
	if cap(w.B) <= 1024 {
		w.B = w.B[:0]
	} else {
		w.B = nil
	}
}

func AESCBCBase64Decrypt(text string, ekey []byte, ikey []byte) ([]byte, error) {
	if n := len(text) % 4; n > 0 {
		text += string([]byte{'=', '=', '='}[:4-n])
	}

	ciphertext, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}

	block, err := aes.NewCipher(ekey)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)

	mode := cipher.NewCBCDecrypter(block, ikey)
	mode.CryptBlocks(plaintext, plaintext)

	plaintext = bytes.TrimRightFunc(plaintext, func(r rune) bool { return !unicode.IsPrint(r) })

	return plaintext, nil
}

func AppendAESCBCBase64Encryption(dst []byte, text []byte, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	n := len(text)
	if i := n % aes.BlockSize; i != 0 {
		n += aes.BlockSize - i
	}

	ciphertext := make([]byte, n)
	copy(ciphertext, text)

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, ciphertext)

	old := len(dst)
	need := base64.URLEncoding.EncodedLen(len(ciphertext))
	for cap(dst)-len(dst) < need {
		dst = append(dst[:cap(dst)], 0)
	}
	base64.URLEncoding.Encode(dst[old:], ciphertext)

	if dst[old+need-1] == '=' {
		need--
	}
	if dst[old+need-1] == '=' {
		need--
	}

	return dst[:old+need]
}

func Chacha20NewStreamCipher(passphrase []byte, nonce uint64) (cipher *chacha20.Cipher, err error) {
	var key []byte
	key, err = hkdf.Key(sha256.New, passphrase, nil, "20151012", 32)
	if err != nil {
		return
	}
	var b [12]byte
	binary.LittleEndian.PutUint64(b[0:], nonce)
	cipher, err = chacha20.NewUnauthenticatedCipher(key, b[:])
	return
}

var _ net.Conn = (*Chacha20NetConn)(nil)

type Chacha20NetConn struct {
	Conn   net.Conn
	Writer *chacha20.Cipher
	Reader *chacha20.Cipher
}

func (c *Chacha20NetConn) NetConn() net.Conn {
	return c.Conn
}

func (c *Chacha20NetConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if c.Reader != nil {
		c.Reader.XORKeyStream(b, b)
	}
	return
}

func (c *Chacha20NetConn) Write(b []byte) (n int, err error) {
	if c.Writer != nil {
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)
		bb.Write(b)
		c.Writer.XORKeyStream(bb.B, bb.B)
		n, err = c.Conn.Write(bb.B)
	} else {
		n, err = c.Conn.Write(b)
	}
	return
}

func (c *Chacha20NetConn) Close() (err error) {
	return c.Conn.Close()
}

func (c *Chacha20NetConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *Chacha20NetConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *Chacha20NetConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *Chacha20NetConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *Chacha20NetConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

type IdleTimeoutConn struct {
	Conn        net.Conn
	IdleTimeout time.Duration

	readat, writeat int64
}

func (c *IdleTimeoutConn) Read(b []byte) (n int, err error) {
	if c.IdleTimeout > 0 {
		now := time.Now()
		if ts := now.Unix(); ts > c.readat {
			c.Conn.SetReadDeadline(now.Add(c.IdleTimeout))
			c.readat = ts
		}
	}
	return c.Conn.Read(b)
}

func (c *IdleTimeoutConn) Write(b []byte) (n int, err error) {
	if c.IdleTimeout > 0 {
		now := time.Now()
		if ts := now.Unix(); ts > c.writeat {
			c.Conn.SetWriteDeadline(now.Add(c.IdleTimeout))
			c.writeat = ts
		}
	}
	return c.Conn.Write(b)
}

func (c *IdleTimeoutConn) Close() error {
	return c.Conn.Close()
}

func (c *IdleTimeoutConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *IdleTimeoutConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *IdleTimeoutConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *IdleTimeoutConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *IdleTimeoutConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func GetNetConnFromServerPreAuthConn(conn ssh.ServerPreAuthConn) (net.Conn, error) {
	s := fmt.Sprintf("%#v", conn)
	if !(strings.HasPrefix(s, "&ssh.connection{transport:(*ssh.handshakeTransport)(") &&
		strings.Contains(s, "sshConn:ssh.sshConn{conn:")) {
		return nil, fmt.Errorf("GetNetConnFromServerPreAuthConn: unsupported ssh connection: %s", s)
	}

	data := (*[2]unsafe.Pointer)(unsafe.Pointer(&conn))[1]
	if data == nil {
		return nil, fmt.Errorf("GetNetConnFromServerPreAuthConn: got an nil *ssh.connection data: %s", s)
	}

	type sshconnection struct {
		transport *struct{}
		sshConn   struct {
			conn net.Conn
		}
	}

	return (*sshconnection)(data).sshConn.conn, nil
}

type HTTPFlushWriter struct {
	http.ResponseWriter
	*http.ResponseController
}

func (w HTTPFlushWriter) Write(p []byte) (n int, err error) {
	n, err = w.ResponseWriter.Write(p)
	if err != nil {
		return 0, err
	}
	//nolint:bodyclose
	err = w.ResponseController.Flush()
	if err != nil {
		return 0, err
	}
	return
}

type HTTPRequestStream struct {
	io.ReadCloser
	http.ResponseWriter
	*http.ResponseController
	raddr *net.TCPAddr
	laddr *net.TCPAddr
}

func (stream HTTPRequestStream) Write(p []byte) (n int, err error) {
	n, err = stream.ResponseWriter.Write(p)
	if err != nil {
		return 0, err
	}
	//nolint:bodyclose
	err = stream.ResponseController.Flush()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (stream HTTPRequestStream) RemoteAddr() net.Addr {
	if stream.raddr == nil {
		return &net.TCPAddr{}
	}
	return stream.raddr
}

func (stream HTTPRequestStream) LocalAddr() net.Addr {
	if stream.laddr == nil {
		return &net.TCPAddr{}
	}
	return stream.laddr
}

func (stream HTTPRequestStream) SetDeadline(t time.Time) error {
	return nil
}

func (stream HTTPRequestStream) SetReadDeadline(t time.Time) error {
	return nil
}

func (stream HTTPRequestStream) SetWriteDeadline(t time.Time) error {
	return nil
}

type TCPListener struct {
	*net.TCPListener
	KeepAlivePeriod time.Duration
	ReadBufferSize  int
	WriteBufferSize int
	TLSConfig       *tls.Config
	Chacha20Key     string
	MirrorHeader    bool
}

func (ln TCPListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	if ln.KeepAlivePeriod > 0 {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(ln.KeepAlivePeriod)
	}
	if ln.ReadBufferSize > 0 {
		tc.SetReadBuffer(ln.ReadBufferSize)
	}
	if ln.WriteBufferSize > 0 {
		tc.SetWriteBuffer(ln.WriteBufferSize)
	}

	c = tc

	if ln.MirrorHeader {
		c = &MirrorHeaderConn{Conn: c}
	}

	switch {
	case ln.TLSConfig != nil:
		c = tls.Server(c, ln.TLSConfig)
	case ln.Chacha20Key != "":
		sha1sum := sha1.Sum([]byte(ln.Chacha20Key))
		nonce := binary.LittleEndian.Uint64(sha1sum[:8])
		c = &Chacha20NetConn{
			Conn:   c,
			Writer: must(Chacha20NewStreamCipher([]byte(ln.Chacha20Key), nonce)),
			Reader: must(Chacha20NewStreamCipher([]byte(ln.Chacha20Key), nonce)),
		}
	}

	return
}

type MirrorHeaderConn struct {
	net.Conn
	header []byte
}

func (c *MirrorHeaderConn) NetConn() net.Conn {
	return c.Conn
}

func (c *MirrorHeaderConn) Header() []byte {
	return c.header
}

func (c *MirrorHeaderConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if c.header == nil {
		c.header = make([]byte, 0, 1500)
	}
	if err == nil && n > 0 && len(c.header) < 1500 {
		c.header = append(c.header, b[:n]...)
	}

	return
}

var _ Dialer = (*MemoryDialer)(nil)

type MemoryDialer struct {
	Session *yamux.Session
	Address string
}

func (d *MemoryDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		break
	default:
		return nil, net.InvalidAddrError("memory dialer network mismatched: " + network)
	}

	if address != d.Address {
		return nil, net.InvalidAddrError("memory dialer network mismatched: " + address + " != " + d.Address)
	}

	return d.Session.Open(ctx)
}

type MemoryListener struct {
	net.Listener

	once  sync.Once
	queue chan struct {
		conn net.Conn
		err  error
	}
}

func (ln *MemoryListener) init() {
	ln.queue = make(chan struct {
		conn net.Conn
		err  error
	}, 2048)
	go func() {
		if ln.Listener == nil {
			return
		}
		for {
			c, err := ln.Listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
			ln.queue <- struct {
				conn net.Conn
				err  error
			}{c, err}
		}
	}()
}

func (ln *MemoryListener) Accept() (c net.Conn, err error) {
	ln.once.Do(ln.init)
	item := <-ln.queue
	c, err = item.conn, item.err
	return
}

func (ln *MemoryListener) Addr() net.Addr {
	if ln.Listener == nil {
		return &net.TCPAddr{}
	}
	return ln.Listener.Addr()
}

func (ln *MemoryListener) Close() (err error) {
	err = ln.Listener.Close()
	for item := range ln.queue {
		if item.conn != nil {
			_ = item.conn.Close()
		}
	}
	return
}

func (ln *MemoryListener) SendConn(c net.Conn) {
	ln.once.Do(ln.init)
	ln.queue <- struct {
		conn net.Conn
		err  error
	}{c, nil}
}

type ConnWithData struct {
	net.Conn
	Data []byte
}

func (c *ConnWithData) Read(b []byte) (int, error) {
	if c.Data == nil {
		return c.Conn.Read(b)
	}

	n := copy(b, c.Data)
	if n < len(c.Data) {
		c.Data = c.Data[n:]
	} else {
		c.Data = nil
	}

	return n, nil
}

type ConnWithBuffers struct {
	net.Conn
	Buffers net.Buffers
}

func (c *ConnWithBuffers) Read(b []byte) (int, error) {
	if c.Buffers == nil {
		return c.Conn.Read(b)
	}

	var total int
	for {
		n := copy(b, c.Buffers[0])
		total += n

		if n < len(c.Buffers[0]) {
			// b is full
			c.Buffers[0] = c.Buffers[0][n:]
			break
		}

		c.Buffers = c.Buffers[1:]
		if len(c.Buffers) == 0 {
			c.Buffers = nil
			break
		}

		b = b[n:]
		if len(b) == 0 {
			break
		}
	}

	return total, nil
}

type ConnOps struct {
	tc *net.TCPConn
	qc *quic.Conn
}

func (ops ConnOps) SupportTCP() bool {
	return ops.tc != nil
}

func (ops ConnOps) SupportQUIC() bool {
	return ops.qc != nil
}

func (ops ConnOps) GetQuicStats() (stats *quic.ConnectionStats, err error) {
	if ops.qc != nil {
		stats = ptr(ops.qc.ConnectionStats())
	}
	return
}

var _ log.ObjectMarshaler = (HTTPHeaderMarshalLogObject)(nil)

type HTTPHeaderMarshalLogObject http.Header

func (o HTTPHeaderMarshalLogObject) MarshalObject(e *log.Entry) {
	for key, values := range o {
		for _, value := range values {
			e.Str(key, value)
		}
	}
}

// IPRange represents a range of IP addresses
type IPRange struct {
	StartInt uint32
	EndInt   uint32
	StartIP  netip.Addr
	EndIP    netip.Addr
	Length   int
}

// GetIPRange calculates the start IP, end IP, and number of IPs in a CIDR range
func GetIPRange(cidr string) (result IPRange, err error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return IPRange{}, err
	}

	startIP := prefix.Addr()
	startIPBytes := startIP.As4()
	startInt := uint32(startIPBytes[0])<<24 | uint32(startIPBytes[1])<<16 | uint32(startIPBytes[2])<<8 | uint32(startIPBytes[3])
	length := 1 << (32 - prefix.Bits()) // Number of IPs in the CIDR block

	// Calculate the end IP by adding the number of IPs in the range to the start IP
	endInt := startInt + uint32(length-1)
	endIP := netip.AddrFrom4([4]byte{
		byte(endInt >> 24),
		byte(endInt >> 16),
		byte(endInt >> 8),
		byte(endInt),
	})

	result = IPRange{
		StartInt: startInt,
		EndInt:   endInt,
		StartIP:  startIP,
		EndIP:    endIP,
		Length:   length,
	}

	return result, nil
}

func LookupEcdsaCiphers(clientHello *tls.ClientHelloInfo) (bool, uint16) {
	for _, cipher := range clientHello.CipherSuites {
		switch cipher {
		case tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256:
			return true, cipher
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			return false, cipher
		case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA:
			return false, 0
		}
	}
	return false, 0
}

func IsTLSGreaseCode(c uint16) bool {
	return c&0x0f0f == 0x0a0a && c&0xff == c>>8
}

func AppendJA3Fingerprint(dst []byte, version TLSVersion, info *tls.ClientHelloInfo) []byte {
	b := AppendableBytes(dst)

	// version
	b = b.Uint64(uint64(version), 10)

	// ciphers
	i := 0
	for _, c := range info.CipherSuites {
		if IsTLSGreaseCode(c) {
			continue
		}
		if i > 0 {
			b = b.Byte('-')
		}
		b = b.Uint64(uint64(c), 10)
		i++
	}
	b = b.Byte(',')

	i = 0
	for _, c := range info.Extensions {
		if IsTLSGreaseCode(c) || c == 0x0015 {
			continue
		}
		if i > 0 {
			b = b.Byte('-')
		}
		b = b.Uint64(uint64(c), 10)
		i++
	}
	b = b.Byte(',')

	// groups
	i = 0
	for _, c := range info.SupportedCurves {
		if IsTLSGreaseCode(uint16(c)) {
			continue
		}
		if i > 0 {
			b = b.Byte('-')
		}
		b = b.Uint64(uint64(c), 10)
		i++
	}
	b = b.Byte(',')

	// formats
	for i, c := range info.SupportedPoints {
		if i > 0 {
			b = b.Byte('-')
		}
		b = b.Uint64(uint64(c), 10)
	}

	return b
}

func AppendJA4Fingerprint(dst []byte, version TLSVersion, info *tls.ClientHelloInfo, isquic bool) []byte {
	b := AppendableBytes(dst)

	ciphers := make([]uint16, 0, 32)
	for _, c := range info.CipherSuites {
		if !IsTLSGreaseCode(c) {
			ciphers = append(ciphers, c)
		}
	}

	extensions, extensionsLength := make([]uint16, 0, 32), 0
	for _, e := range info.Extensions {
		if !IsTLSGreaseCode(e) {
			// now remove SNI and ALPN values
			if e != 0x0000 && e != 0x0010 {
				extensions = append(extensions, e)
			}
			extensionsLength++
		}
	}

	if isquic {
		b = b.Byte('q')
	} else {
		b = b.Byte('t')
	}
	switch version {
	case TLSVersion13:
		b = b.Str("13")
	case TLSVersion12:
		b = b.Str("12")
	case TLSVersion11:
		b = b.Str("11")
	case TLSVersion10:
		b = b.Str("10")
	default:
		b = b.Str("00")
	}
	if info.ServerName != "" {
		b = b.Byte('d')
	} else {
		b = b.Byte('i')
	}
	if i := uint64(len(ciphers)); i < 10 {
		b = b.Byte('0').Uint64(i, 10)
	} else {
		b = b.Uint64(i, 10)
	}
	if i := uint64(extensionsLength); i < 10 {
		b = b.Byte('0').Uint64(i, 10)
	} else {
		b = b.Uint64(i, 10)
	}
	if len(info.SupportedProtos) != 0 && len(info.SupportedProtos[0]) >= 2 {
		b = b.Str(info.SupportedProtos[0][:2])
	} else {
		b = b.Str("00")
	}

	b = b.Byte('_')

	buf := AppendableBytes(make([]byte, 0, 128))

	if len(ciphers) != 0 {
		slices.Sort(ciphers)
		buf = buf[:0]
		for _, c := range ciphers {
			switch {
			case c < 0x10:
				buf = buf.Str("000").Uint64(uint64(c), 16)
			case c < 0x100:
				buf = buf.Str("00").Uint64(uint64(c), 16)
			case c < 0x1000:
				buf = buf.Str("0").Uint64(uint64(c), 16)
			default:
				buf = buf.Uint64(uint64(c), 16)
			}
			buf = buf.Byte(',')
		}
		sum := sha256.Sum256(buf[:len(buf)-1])
		b = b.Hex(sum[:6])
	} else {
		b = b.Str("000000000000")
	}

	b = b.Byte('_')

	if len(extensions) != 0 {
		slices.Sort(extensions)
		buf = buf[:0]
		for _, c := range extensions {
			switch {
			case c < 0x10:
				buf = buf.Str("000").Uint64(uint64(c), 16)
			case c < 0x100:
				buf = buf.Str("00").Uint64(uint64(c), 16)
			case c < 0x1000:
				buf = buf.Str("0").Uint64(uint64(c), 16)
			default:
				buf = buf.Uint64(uint64(c), 16)
			}
			buf = buf.Byte(',')
		}
		if len(info.SignatureSchemes) != 0 {
			buf[len(buf)-1] = '_'
			for _, c := range info.SignatureSchemes {
				switch {
				case IsTLSGreaseCode(uint16(c)):
					continue
				case c < 0x10:
					buf = buf.Str("000").Uint64(uint64(c), 16)
				case c < 0x100:
					buf = buf.Str("00").Uint64(uint64(c), 16)
				case c < 0x1000:
					buf = buf.Str("0").Uint64(uint64(c), 16)
				default:
					buf = buf.Uint64(uint64(c), 16)
				}
				buf = buf.Byte(',')
			}
		}
		sum := sha256.Sum256(buf[:len(buf)-1])
		b = b.Hex(sum[:6])
	} else {
		b = b.Str("000000000000")
	}

	return b
}

func GetPreferedLocalIP(remote string) (netip.Addr, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(remote, "443"))
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()

	return AddrPortFromNetAddr(conn.LocalAddr()).Addr(), nil
}

func AddrPortFromNetAddr(addr net.Addr) (addrport netip.AddrPort) {
	switch v := addr.(type) {
	case *net.TCPAddr:
		addrport = v.AddrPort()
	case *net.UDPAddr:
		addrport = v.AddrPort()
	default:
		addrport, _ = netip.ParseAddrPort(v.String())
	}
	if addr := addrport.Addr(); addr.Is4In6() {
		addrport = netip.AddrPortFrom(netip.AddrFrom4(addr.As4()), addrport.Port())
	}
	return
}

var _ net.Addr = PlainAddr{}

type PlainAddr struct {
	Addr [16]byte
	Port uint16
}

func (addr PlainAddr) AddrPort() netip.AddrPort {
	var ip netip.Addr
	a := (*[2]uint64)((unsafe.Pointer)(&addr))
	// see https://cs.opensource.google/go/go/+/refs/tags/go1.25.0:src/net/netip/netip.go;l=469
	if a[0] == 0 && a[1]>>32 == 0xffff {
		if IsLittleEndian {
			ip = netip.AddrFrom4([4]byte{addr.Addr[11], addr.Addr[10], addr.Addr[9], addr.Addr[8]})
		} else {
			ip = netip.AddrFrom4([4]byte{addr.Addr[12], addr.Addr[13], addr.Addr[14], addr.Addr[15]})
		}
	} else {
		ip = netip.AddrFrom16(addr.Addr)
	}
	return netip.AddrPortFrom(ip, addr.Port)
}

func (addr PlainAddr) AppendTo(b []byte) []byte {
	a := (*[2]uint64)((unsafe.Pointer)(&addr))
	// see https://cs.opensource.google/go/go/+/refs/tags/go1.25.0:src/net/netip/netip.go;l=469
	if a[0] == 0 && a[1]>>32 == 0xffff {
		b = strconv.AppendUint(b, uint64(addr.Addr[11]), 10)
		b = append(b, '.')
		b = strconv.AppendUint(b, uint64(addr.Addr[10]), 10)
		b = append(b, '.')
		b = strconv.AppendUint(b, uint64(addr.Addr[9]), 10)
		b = append(b, '.')
		b = strconv.AppendUint(b, uint64(addr.Addr[8]), 10)
		b = append(b, ':')
		b = strconv.AppendUint(b, uint64(addr.Port), 10)
	} else {
		b = append(b, '[')
		b = netip.AddrFrom16(addr.Addr).AppendTo(b)
		b = append(b, ']', ':')
		b = strconv.AppendUint(b, uint64(addr.Port), 10)
	}
	return b
}

func (addr PlainAddr) String() string {
	return string(addr.AppendTo(make([]byte, 0, 48)))
}

func (addr PlainAddr) Network() string {
	return ""
}

func PlainAddrFromAddrPort(addrport netip.AddrPort) (addr PlainAddr) {
	addr.Addr = *(*[16]byte)((unsafe.Pointer)(&addrport))
	addr.Port = addrport.Port()
	return
}

func PlainAddrFromTCPAddr(na *net.TCPAddr) (addr PlainAddr) {
	ip, _ := netip.AddrFromSlice(na.IP)
	addr.Addr = *(*[16]byte)((unsafe.Pointer)(&ip))
	addr.Port = uint16(na.Port)
	return
}

func PlainAddrFromUDPAddr(na *net.UDPAddr) (addr PlainAddr) {
	ip, _ := netip.AddrFromSlice(na.IP)
	addr.Addr = *(*[16]byte)((unsafe.Pointer)(&ip))
	addr.Port = uint16(na.Port)
	return
}

func PlainAddrFromNetAddr(na net.Addr) (addr PlainAddr) {
	switch v := na.(type) {
	case *net.TCPAddr:
		addr = PlainAddrFromTCPAddr(v)
	case *net.UDPAddr:
		addr = PlainAddrFromUDPAddr(v)
	case PlainAddr:
		addr = v
	default:
		addr = PlainAddrFromAddrPort(netip.MustParseAddrPort(v.String()))
	}
	return
}

// see https://en.wikipedia.org/wiki/Reserved_IP_addresses
func IsReservedIP(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	switch b[0] {
	case 0:
		return true
	case 10:
		return true
	case 100:
		return b[1] >= 64 && b[1] <= 127
	case 127:
		return true
	case 169:
		return b[1] == 254
	case 172:
		return b[1] >= 16 && b[1] <= 31
	case 192:
		switch b[1] {
		case 0:
			switch b[2] {
			case 0, 2:
				return true
			}
		case 18, 19:
			return true
		case 88:
			return b[2] == 99
		case 168:
			return true
		}
	case 198:
		switch b[1] {
		case 18, 19:
			return true
		case 51:
			return b[2] == 100
		}
	case 203:
		return b[1] == 0 && b[2] == 113
	case 224:
		return true
	case 240:
		return true
	}
	return false
}

// see https://www.cloudflare.com/ips/
func IsCloudflareIP(ip netip.Addr) bool {
	ip = ip.Unmap()

	if ip.Is4() {
		b := ip.As4()
		switch b[0] {
		case 103:
			switch b[1] {
			case 21:
				return b[2] >= 244 && b[2] <= 247
			case 22:
				return b[2] >= 200 && b[2] <= 203
			case 31:
				return b[2] >= 4 && b[2] <= 7
			}
		case 104:
			return b[1] >= 16 && b[1] <= 27
		case 108:
			return b[1] == 162 && b[2] >= 192
		case 131:
			return b[1] == 0 && b[2] >= 72 && b[2] <= 75
		case 141:
			return b[1] == 101 && b[2] >= 64 && b[2] <= 127
		case 162:
			return b[1] >= 158 && b[1] <= 159
		case 172:
			return b[1] >= 64 && b[1] <= 71
		case 173:
			return b[1] == 245 && b[2] >= 48 && b[2] <= 63
		case 188:
			return b[1] == 114 && b[2] >= 96 && b[2] <= 111
		case 190:
			return b[1] == 93 && b[2] >= 240
		case 197:
			return b[1] == 234 && b[2] >= 240 && b[2] <= 243
		case 198:
			return b[1] == 41 && b[2] >= 128
		}
		return false
	}

	if !ip.Is6() {
		return false
	}

	b := ip.As16()
	prefix32 := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	switch prefix32 {
	case 0x2400cb00,
		0x26064700,
		0x2803f800,
		0x2405b500,
		0x24058100,
		0x2c0ff248:
		return true
	}

	if prefix32>>3 == 0x2a0698c0>>3 {
		return true
	}

	return false
}

func IsBogusChinaIP(ip netip.Addr) (ok bool) {
	if ip.Is6() {
		return false
	}

	ip4 := ip.As4()
	n := ((uint(ip4[0])<<8+uint(ip4[1]))<<8+uint(ip4[2]))<<8 + uint(ip4[3])

	_, ok = bogusChinaIP[n]
	return
}

var bogusChinaIP = map[uint]bool{
	((10<<8+10)<<8+10)<<8 + 10:     true,
	((101<<8+226)<<8+10)<<8 + 8:    true,
	((104<<8+239)<<8+213)<<8 + 7:   true,
	((110<<8+249)<<8+209)<<8 + 42:  true,
	((111<<8+11)<<8+208)<<8 + 2:    true,
	((111<<8+175)<<8+221)<<8 + 58:  true,
	((112<<8+132)<<8+230)<<8 + 179: true,
	((113<<8+11)<<8+194)<<8 + 190:  true,
	((113<<8+12)<<8+83)<<8 + 4:     true,
	((113<<8+12)<<8+83)<<8 + 5:     true,
	((114<<8+112)<<8+163)<<8 + 232: true,
	((114<<8+112)<<8+163)<<8 + 254: true,
	((120<<8+192)<<8+83)<<8 + 163:  true,
	((120<<8+209)<<8+138)<<8 + 64:  true,
	((123<<8+125)<<8+81)<<8 + 12:   true,
	((123<<8+126)<<8+249)<<8 + 238: true,
	((123<<8+129)<<8+254)<<8 + 11:  true,
	((123<<8+129)<<8+254)<<8 + 12:  true,
	((123<<8+129)<<8+254)<<8 + 13:  true,
	((123<<8+129)<<8+254)<<8 + 14:  true,
	((123<<8+129)<<8+254)<<8 + 15:  true,
	((123<<8+129)<<8+254)<<8 + 16:  true,
	((123<<8+129)<<8+254)<<8 + 17:  true,
	((123<<8+129)<<8+254)<<8 + 18:  true,
	((123<<8+129)<<8+254)<<8 + 19:  true,
	((124<<8+232)<<8+132)<<8 + 94:  true,
	((125<<8+211)<<8+213)<<8 + 130: true,
	((125<<8+211)<<8+213)<<8 + 131: true,
	((125<<8+211)<<8+213)<<8 + 132: true,
	((125<<8+211)<<8+213)<<8 + 133: true,
	((125<<8+211)<<8+213)<<8 + 134: true,
	((125<<8+76)<<8+239)<<8 + 244:  true,
	((125<<8+76)<<8+239)<<8 + 245:  true,
	((127<<8+0)<<8+0)<<8 + 2:       true,
	((180<<8+153)<<8+103)<<8 + 224: true,
	((180<<8+168)<<8+41)<<8 + 175:  true,
	((183<<8+207)<<8+232)<<8 + 253: true,
	((183<<8+221)<<8+242)<<8 + 172: true,
	((183<<8+221)<<8+250)<<8 + 11:  true,
	((183<<8+224)<<8+40)<<8 + 24:   true,
	((198<<8+105)<<8+254)<<8 + 11:  true,
	((202<<8+100)<<8+220)<<8 + 54:  true,
	((202<<8+100)<<8+68)<<8 + 117:  true,
	((202<<8+102)<<8+110)<<8 + 203: true,
	((202<<8+102)<<8+110)<<8 + 204: true,
	((202<<8+102)<<8+110)<<8 + 205: true,
	((202<<8+106)<<8+1)<<8 + 2:     true,
	((202<<8+106)<<8+199)<<8 + 34:  true,
	((202<<8+106)<<8+199)<<8 + 35:  true,
	((202<<8+106)<<8+199)<<8 + 36:  true,
	((202<<8+106)<<8+199)<<8 + 37:  true,
	((202<<8+106)<<8+199)<<8 + 38:  true,
	((202<<8+98)<<8+24)<<8 + 121:   true,
	((202<<8+98)<<8+24)<<8 + 122:   true,
	((202<<8+98)<<8+24)<<8 + 123:   true,
	((202<<8+98)<<8+24)<<8 + 124:   true,
	((202<<8+98)<<8+24)<<8 + 125:   true,
	((202<<8+99)<<8+254)<<8 + 230:  true,
	((202<<8+99)<<8+254)<<8 + 231:  true,
	((202<<8+99)<<8+254)<<8 + 232:  true,
	((211<<8+136)<<8+113)<<8 + 1:   true,
	((211<<8+137)<<8+130)<<8 + 101: true,
	((211<<8+138)<<8+102)<<8 + 198: true,
	((211<<8+138)<<8+34)<<8 + 204:  true,
	((211<<8+138)<<8+74)<<8 + 132:  true,
	((211<<8+139)<<8+136)<<8 + 73:  true,
	((211<<8+94)<<8+66)<<8 + 147:   true,
	((211<<8+98)<<8+70)<<8 + 195:   true,
	((211<<8+98)<<8+70)<<8 + 226:   true,
	((211<<8+98)<<8+70)<<8 + 227:   true,
	((211<<8+98)<<8+71)<<8 + 195:   true,
	((218<<8+28)<<8+144)<<8 + 36:   true,
	((218<<8+28)<<8+144)<<8 + 37:   true,
	((218<<8+28)<<8+144)<<8 + 38:   true,
	((218<<8+28)<<8+144)<<8 + 39:   true,
	((218<<8+28)<<8+144)<<8 + 40:   true,
	((218<<8+28)<<8+144)<<8 + 41:   true,
	((218<<8+28)<<8+144)<<8 + 42:   true,
	((218<<8+30)<<8+64)<<8 + 194:   true,
	((218<<8+68)<<8+250)<<8 + 117:  true,
	((218<<8+68)<<8+250)<<8 + 118:  true,
	((218<<8+68)<<8+250)<<8 + 119:  true,
	((218<<8+68)<<8+250)<<8 + 120:  true,
	((218<<8+68)<<8+250)<<8 + 121:  true,
	((218<<8+93)<<8+250)<<8 + 18:   true,
	((219<<8+146)<<8+13)<<8 + 36:   true,
	((220<<8+165)<<8+8)<<8 + 172:   true,
	((220<<8+165)<<8+8)<<8 + 174:   true,
	((220<<8+250)<<8+64)<<8 + 18:   true,
	((220<<8+250)<<8+64)<<8 + 19:   true,
	((220<<8+250)<<8+64)<<8 + 20:   true,
	((220<<8+250)<<8+64)<<8 + 21:   true,
	((220<<8+250)<<8+64)<<8 + 22:   true,
	((220<<8+250)<<8+64)<<8 + 225:  true,
	((220<<8+250)<<8+64)<<8 + 226:  true,
	((220<<8+250)<<8+64)<<8 + 227:  true,
	((220<<8+250)<<8+64)<<8 + 228:  true,
	((220<<8+250)<<8+64)<<8 + 23:   true,
	((220<<8+250)<<8+64)<<8 + 24:   true,
	((220<<8+250)<<8+64)<<8 + 25:   true,
	((220<<8+250)<<8+64)<<8 + 26:   true,
	((220<<8+250)<<8+64)<<8 + 27:   true,
	((220<<8+250)<<8+64)<<8 + 28:   true,
	((220<<8+250)<<8+64)<<8 + 29:   true,
	((220<<8+250)<<8+64)<<8 + 30:   true,
	((221<<8+179)<<8+46)<<8 + 190:  true,
	((221<<8+179)<<8+46)<<8 + 194:  true,
	((221<<8+192)<<8+153)<<8 + 41:  true,
	((221<<8+192)<<8+153)<<8 + 42:  true,
	((221<<8+192)<<8+153)<<8 + 43:  true,
	((221<<8+192)<<8+153)<<8 + 44:  true,
	((221<<8+192)<<8+153)<<8 + 45:  true,
	((221<<8+192)<<8+153)<<8 + 46:  true,
	((221<<8+192)<<8+153)<<8 + 49:  true,
	((221<<8+204)<<8+244)<<8 + 36:  true,
	((221<<8+204)<<8+244)<<8 + 37:  true,
	((221<<8+204)<<8+244)<<8 + 38:  true,
	((221<<8+204)<<8+244)<<8 + 39:  true,
	((221<<8+204)<<8+244)<<8 + 40:  true,
	((221<<8+204)<<8+244)<<8 + 41:  true,
	((221<<8+8)<<8+69)<<8 + 27:     true,
	((222<<8+221)<<8+5)<<8 + 204:   true,
	((222<<8+221)<<8+5)<<8 + 252:   true,
	((222<<8+221)<<8+5)<<8 + 253:   true,
	((223<<8+82)<<8+248)<<8 + 117:  true,
	((243<<8+185)<<8+187)<<8 + 3:   true,
	((243<<8+185)<<8+187)<<8 + 30:  true,
	((243<<8+185)<<8+187)<<8 + 39:  true,
	((249<<8+129)<<8+46)<<8 + 48:   true,
	((253<<8+157)<<8+14)<<8 + 165:  true,
	((255<<8+255)<<8+255)<<8 + 255: true,
	((42<<8+123)<<8+125)<<8 + 237:  true,
	((60<<8+19)<<8+29)<<8 + 21:     true,
	((60<<8+19)<<8+29)<<8 + 22:     true,
	((60<<8+19)<<8+29)<<8 + 23:     true,
	((60<<8+19)<<8+29)<<8 + 24:     true,
	((60<<8+19)<<8+29)<<8 + 25:     true,
	((60<<8+19)<<8+29)<<8 + 26:     true,
	((60<<8+19)<<8+29)<<8 + 27:     true,
	((60<<8+191)<<8+124)<<8 + 236:  true,
	((60<<8+191)<<8+124)<<8 + 252:  true,
	((61<<8+131)<<8+208)<<8 + 210:  true,
	((61<<8+131)<<8+208)<<8 + 211:  true,
	((61<<8+139)<<8+8)<<8 + 101:    true,
	((61<<8+139)<<8+8)<<8 + 102:    true,
	((61<<8+139)<<8+8)<<8 + 103:    true,
	((61<<8+139)<<8+8)<<8 + 104:    true,
	((61<<8+183)<<8+1)<<8 + 186:    true,
	((61<<8+191)<<8+206)<<8 + 4:    true,
	((61<<8+54)<<8+28)<<8 + 6:      true,
}

func ReadFile(s string) (body []byte, err error) {
	if s == "-" {
		return io.ReadAll(os.Stdin)
	}

	var u *url.URL

	u, err = url.Parse(s)
	if err != nil {
		return
	}

	switch u.Scheme {
	case "":
		body, err = os.ReadFile(s)
	case "http", "https":
		var resp *http.Response
		resp, err = http.Get(s)
		if err == nil {
			defer resp.Body.Close()
			body, err = io.ReadAll(resp.Body)
		}
	default:
		err = errors.New("unsupported url: " + s)
	}

	return
}

func SetHTTP2ResponseWriterSentHeader(rw http.ResponseWriter, sent bool) error {
	if rw == nil {
		return errors.New("SetHTTP2ResponseWriterSentHeader got an empty http.ResponseWriter interface")
	}

	data := (*[2]unsafe.Pointer)(unsafe.Pointer(&rw))[1]
	if data == nil {
		return errors.New("SetHTTP2ResponseWriterSentHeader got an empty http.ResponseWriter data")
	}

	type responseWriter struct {
		rws *struct {
			stream        uintptr
			req           *http.Request
			conn          uintptr
			bw            *bufio.Writer // writing to a chunkWriter{this *responseWriterState}
			handlerHeader http.Header   // nil until called
			snapHeader    http.Header   // snapshot of handlerHeader at WriteHeader time
			trailers      []string      // set in writeChunk
			status        int           // status code passed to WriteHeader
			wroteHeader   bool          // WriteHeader called (explicitly or implicitly). Not necessarily sent to user yet.
			sentHeader    bool          // have we sent the header frame?
			handlerDone   bool          // handler has finished
		}
	}

	(*responseWriter)(data).rws.wroteHeader = sent
	(*responseWriter)(data).rws.sentHeader = sent
	(*responseWriter)(data).rws.handlerDone = !sent

	return nil
}

func GetOCSPStaple(ctx context.Context, transport http.RoundTripper, cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("Nil x509 certificate")
	}

	if len(cert.OCSPServer) == 0 {
		return nil, errors.New("No OCSP server in certificate")
	}

	if len(cert.IssuingCertificateURL) == 0 {
		return nil, errors.New("no URL to issuing certificate")
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cert.IssuingCertificateURL[0], nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("getting issuer certificate: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading issuer certificate: %w", err)
	}

	issuer, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer certificate: %w", err)
	}

	b, err = ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(b)

	resp, err = http.Post(cert.OCSPServer[0], "text/ocsp", r)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if _, err := ocsp.ParseResponse(raw, issuer); err != nil {
		return nil, err
	}

	return raw, nil
}

// WildcardMatch from https://github.com/IGLOU-EU/go-wildcard
func WildcardMatch(pattern, s string) bool {
	if pattern == "" {
		return s == pattern
	}
	if pattern == "*" || s == pattern {
		return true
	}

	var lastErotemeByte byte
	var patternIndex, sIndex, lastStar, lastEroteme int
	patternLen := len(pattern)
	sLen := len(s)
	star := -1
	eroteme := -1

Loop:
	if sIndex >= sLen {
		goto checkPattern
	}

	if patternIndex >= patternLen {
		if star != -1 {
			patternIndex = star + 1
			lastStar++
			sIndex = lastStar
			goto Loop
		}
		return false
	}
	switch pattern[patternIndex] {
	case '.':
		// It matches any single character. So, we don't need to check anything.
	case '?':
		// '?' matches one character. Store its position and match exactly one character in the string.
		eroteme = patternIndex
		lastEroteme = sIndex
		lastErotemeByte = s[sIndex]
	case '*':
		// '*' matches zero or more characters. Store its position and increment the pattern index.
		star = patternIndex
		lastStar = sIndex
		patternIndex++
		goto Loop
	default:
		// If the characters don't match, check if there was a previous '?' or '*' to backtrack.
		if pattern[patternIndex] != s[sIndex] {
			if eroteme != -1 {
				patternIndex = eroteme + 1
				sIndex = lastEroteme
				eroteme = -1
				goto Loop
			}

			if star != -1 {
				patternIndex = star + 1
				lastStar++
				sIndex = lastStar
				goto Loop
			}

			return false
		}

		// If the characters match, check if it was not the same to validate the eroteme.
		if eroteme != -1 && lastErotemeByte != s[sIndex] {
			eroteme = -1
		}
	}

	patternIndex++
	sIndex++
	goto Loop

	// Check if the remaining pattern characters are '*' or '?', which can match the end of the string.
checkPattern:
	if patternIndex < patternLen {
		if pattern[patternIndex] == '*' {
			patternIndex++
			goto checkPattern
		} else if pattern[patternIndex] == '?' {
			if sIndex >= sLen {
				sIndex--
			}
			patternIndex++
			goto checkPattern
		}
	}

	return patternIndex == patternLen
}

type SlogWriter struct {
	Logger *slog.Logger
}

func (w SlogWriter) Write(b []byte) (int, error) {
	if w.Logger != nil {
		w.Logger.Info(b2s(b))
	}
	return len(b), nil
}

type FileLoader[T any] struct {
	Filename     string
	Unmarshal    func([]byte, any) error
	PollDuration time.Duration
	Logger       *slog.Logger

	once  sync.Once
	mtime int64
	ptr   unsafe.Pointer
}

func (f *FileLoader[T]) load() {
	if f.Unmarshal == nil {
		if f.Logger != nil {
			f.Logger.Error("FileLoader: empty unmarshal", "filename", f.Filename)
		}
		return
	}
	data, err := os.ReadFile(f.Filename)
	if err != nil {
		if f.Logger != nil {
			f.Logger.Error("FileLoader: read file failed", "filename", f.Filename, "error", err)
		}
		return
	}
	v := new(T)
	err = f.Unmarshal(data, v)
	if err != nil {
		if f.Logger != nil {
			f.Logger.Error("FileLoader: unmarshal data failed", "filename", f.Filename, "error", err)
		}
		return
	}
	atomic.StorePointer(&f.ptr, (unsafe.Pointer)(v))
}

func (f *FileLoader[T]) Load() *T {
	f.once.Do(func() {
		f.load()
		go func() {
			dur := f.PollDuration
			if dur == 0 {
				dur = time.Minute
			}
			for range time.Tick(dur) {
				fi, err := os.Stat(f.Filename)
				if err != nil {
					if f.Logger != nil {
						f.Logger.Error("FileLoader: stat file error", "filename", f.Filename, "error", err)
					}
					continue
				}
				mtime := fi.ModTime().Unix()
				if mtime != atomic.SwapInt64(&f.mtime, mtime) {
					f.load()
				}
			}
		}()
	})

	return (*T)(atomic.LoadPointer(&f.ptr))
}

type CachingMap[K comparable, V any] struct {
	// double buffering mechanism
	index int64
	maps  [2]map[K]V

	// write queue
	queue chan struct {
		key   K
		value V
	}

	getter   func(K) (V, error)
	maxsize  int
	duration time.Duration
}

func NewCachingMap[K comparable, V any](getter func(K) (V, error), maxsize int, duration time.Duration) *CachingMap[K, V] {
	cm := &CachingMap[K, V]{
		index: 0,
		maps: [2]map[K]V{
			make(map[K]V),
			make(map[K]V),
		},
		queue: make(chan struct {
			key   K
			value V
		}, 1024),
		getter:   getter,
		maxsize:  maxsize,
		duration: duration,
	}
	go func(cm *CachingMap[K, V]) {
		duration := cm.duration
		if duration == 0 {
			duration = time.Minute
		}
		ticker := time.NewTicker(duration)
		for {
			select {
			case kv := <-cm.queue:
				cm.maps[(atomic.LoadInt64(&cm.index)+1)%2][kv.key] = kv.value
			case <-ticker.C:
				atomic.StoreInt64(&cm.index, (atomic.LoadInt64(&cm.index)+1)%2)
				if m := cm.maps[(atomic.LoadInt64(&cm.index)+1)%2]; maxsize <= 0 || len(m) <= maxsize {
					maps.Copy(m, cm.maps[atomic.LoadInt64(&cm.index)])
				} else {
					cm.maps[(atomic.LoadInt64(&cm.index)+1)%2] = make(map[K]V)
				}
			}
		}
	}(cm)
	return cm
}

func (cm *CachingMap[K, V]) Get(key K) (value V, ok bool, err error) {
	// fast path, lock-free
	value, ok = cm.maps[atomic.LoadInt64(&cm.index)][key]
	if ok {
		return
	}

	// slow path
	value, err = cm.getter(key)
	if err == nil {
		cm.queue <- struct {
			key   K
			value V
		}{key, value}
	}

	return
}

func GetMaxProcsFromCgroupV2() int {
	data, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return 0
	}

	fields := strings.Fields(string(data))
	if len(fields) != 2 || fields[0] == "max" {
		return 0
	}

	quota, err1 := strconv.Atoi(fields[0])
	period, err2 := strconv.Atoi(fields[1])

	if err1 != nil || err2 != nil || period <= 0 {
		return 0
	}

	n := (quota + period - 1) / period

	return n
}
