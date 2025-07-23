package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unsafe"

	"github.com/libp2p/go-yamux/v5"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/zeebo/wyhash"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/ocsp"
)

// fastrand returns a pseudorandom uint32.
//
//go:noescape
//go:linkname fastrand runtime.cheaprand
func fastrand() uint32

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

type IPInt uint32

func NewIPInt(ip string) IPInt {
	var dots int
	var i, j IPInt
	for k := range ip {
		switch ip[k] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			j = j*10 + IPInt(ip[k]-'0')
		case '.':
			if j >= 256 {
				return 0
			}
			i = i*256 + j
			j = 0
			dots++
		default:
			return 0
		}
	}
	if dots != 3 || j >= 256 {
		return 0
	}
	return i*256 + j
}

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

func AppendTemplate(dst []byte, template string, startTag, endTag byte, m map[string]interface{}, stripSpace bool) []byte {
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

func Chacha20NewEncryptStreamCipher(passphrase []byte) (cipher *chacha20.Cipher, nonce []byte, err error) {
	var key []byte
	key, err = hkdf.Key(sha256.New, passphrase, nil, "20151012", 32)
	if err != nil {
		return
	}
	nonce = make([]byte, 12)
	binary.NativeEndian.PutUint32(nonce[0:], fastrand())
	binary.NativeEndian.PutUint32(nonce[4:], fastrand())
	binary.NativeEndian.PutUint32(nonce[8:], fastrand())
	cipher, err = chacha20.NewUnauthenticatedCipher(key, nonce)
	return
}

func Chacha20NewDecryptStreamCipher(passphrase []byte, nonce []byte) (cipher *chacha20.Cipher, err error) {
	var key []byte
	key, err = hkdf.Key(sha256.New, passphrase, nil, "20151012", 32)
	if err != nil {
		return
	}
	cipher, err = chacha20.NewUnauthenticatedCipher(key, nonce)
	return
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
		c = &MirrorHeaderConn{Conn: c, Header: nil}
	}

	if ln.TLSConfig != nil {
		c = tls.Server(c, ln.TLSConfig)
	}

	return
}

type MirrorHeaderConn struct {
	net.Conn
	Header []byte
}

func (c *MirrorHeaderConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if c.Header == nil {
		c.Header = make([]byte, 0, 1500)
	}
	if err == nil && n > 0 && len(c.Header) < 1500 {
		c.Header = append(c.Header, b[:n]...)
	}

	return
}

func GetMirrorHeader(conn net.Conn) []byte {
	if c, ok := conn.(*tls.Conn); ok && c != nil {
		// conn = (*struct{ conn net.Conn })(unsafe.Pointer(c)).conn
		conn = c.NetConn()
	}
	if c, ok := conn.(*MirrorHeaderConn); ok && c.Header != nil && len(c.Header) > 0 {
		return c.Header
	}
	return nil
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

func GetPreferedLocalIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	s, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil, err
	}

	return net.ParseIP(s), nil
}

// see https://en.wikipedia.org/wiki/Reserved_IP_addresses
func IsReservedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch ip4[0] {
		case 10:
			return true
		case 100:
			return ip4[1] >= 64 && ip4[1] <= 127
		case 127:
			return true
		case 169:
			return ip4[1] == 254
		case 172:
			return ip4[1] >= 16 && ip4[1] <= 31
		case 192:
			switch ip4[1] {
			case 0:
				switch ip4[2] {
				case 0, 2:
					return true
				}
			case 18, 19:
				return true
			case 51:
				return ip4[2] == 100
			case 88:
				return ip4[2] == 99
			case 168:
				return true
			}
		case 203:
			return ip4[1] == 0 && ip4[2] == 113
		case 224:
			return true
		case 240:
			return true
		}
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

type UserInfo struct {
	Username string
	Password string
	Attrs    map[string]any
}

/*

username,password,speed_limit,allow_tunnel,allow_client,allow_ssh,allow_webdav
foo,123456,-1,1,0,0,0
bar,qwerty,0,0,1,0,0

*/

var usercsvloaders = xsync.NewMap[string, *FileLoader[[]UserInfo]](xsync.WithSerialResize())

func GetUserInfoCsvLoader(authTableFile string) (loader *FileLoader[[]UserInfo]) {
	loader, _ = usercsvloaders.LoadOrCompute(authTableFile, func() (*FileLoader[[]UserInfo], bool) {
		return &FileLoader[[]UserInfo]{
			Filename:     authTableFile,
			PollDuration: 15 * time.Second,
			Logger:       slog.Default(),
			Unmarshal: func(data []byte, v any) error {
				infos, ok := v.(*[]UserInfo)
				if !ok {
					return fmt.Errorf("*[]UserInfo required, found %T", v)
				}

				records, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
				if err != nil {
					return err
				}
				if len(records) <= 1 {
					return fmt.Errorf("no csv rows in %q", data)
				}

				names := records[0]
				for _, parts := range records[1:] {
					if len(parts) <= 1 {
						continue
					}
					var user UserInfo
					for i, part := range parts {
						switch i {
						case 0:
							user.Username = part
						case 1:
							user.Password = part
						default:
							if user.Attrs == nil {
								user.Attrs = make(map[string]any)
							}
							if i >= len(names) {
								return fmt.Errorf("overflow csv cloumn, names=%v parts=%v", names, parts)
							}
							user.Attrs[names[i]] = part
						}
					}
					*infos = append(*infos, user)
				}
				slices.SortFunc(*infos, func(a, b UserInfo) int {
					return cmp.Compare(a.Username, b.Username)
				})
				return nil
			},
		}, false
	})
	return
}

var argon2idRegex = regexp.MustCompile(`^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$(.+)\$(.+)$`)

func LookupUserInfoFromCsvLoader(userloader *FileLoader[[]UserInfo], user *UserInfo) (err error) {
	records := *userloader.Load()
	i, ok := slices.BinarySearchFunc(records, *user, func(a, b UserInfo) int { return cmp.Compare(a.Username, b.Username) })
	switch {
	case !ok:
		err = fmt.Errorf("invalid username: %v", user.Username)
	case user.Password == records[i].Password:
		*user = records[i]
	case strings.HasPrefix(records[i].Password, "0x"):
		var b []byte
		b, err = hex.AppendDecode(make([]byte, 0, 64), s2b(records[i].Password[2:]))
		if err != nil {
			err = fmt.Errorf("invalid sha1/sha256 password: %v", records[i].Password)
			return
		}
		switch len(b) {
		case 8:
			if binary.BigEndian.Uint64(b) == wyhash.HashString(user.Password, 0) {
				*user = records[i]
				return
			}
		case 20:
			if *(*[20]byte)(b) == sha1.Sum(s2b(user.Password)) {
				*user = records[i]
				return
			}
		case 32:
			if *(*[32]byte)(b) == sha256.Sum256(s2b(user.Password)) {
				*user = records[i]
				return
			}
		}
		err = fmt.Errorf("invalid md5/sha1/sha256 password: %v", records[i].Password)
		return
	case strings.HasPrefix(records[i].Password, "$2y$"):
		err = bcrypt.CompareHashAndPassword([]byte(records[i].Password), []byte(user.Password))
		if err == nil {
			*user = records[i]
		} else {
			err = fmt.Errorf("wrong password: %v: %w", user.Username, err)
		}
	case strings.HasPrefix(records[i].Password, "$argon2id$"):
		// see https://github.com/alexedwards/argon2id
		// $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
		ms := argon2idRegex.FindStringSubmatch(records[i].Password)
		if ms == nil {
			err = fmt.Errorf("invalid argon2id password: %v", records[i].Password)
			return
		}
		m, t, p := first(strconv.Atoi(ms[2])), first(strconv.Atoi(ms[3])), first(strconv.Atoi(ms[4]))
		var salt, key []byte
		salt, err = base64.RawStdEncoding.Strict().DecodeString(ms[5])
		if err != nil {
			err = fmt.Errorf("invalid argon2id password: %v : %w", records[i].Password, err)
			return
		}
		key, err = base64.RawStdEncoding.Strict().DecodeString(ms[6])
		if err != nil {
			err = fmt.Errorf("invalid argon2id password: %v : %w", records[i].Password, err)
			return
		}
		idkey := argon2.IDKey([]byte(user.Password), salt, uint32(t), uint32(m), uint8(p), uint32(len(key)))
		if subtle.ConstantTimeEq(int32(len(key)), int32(len(idkey))) == 0 ||
			subtle.ConstantTimeCompare(key, idkey) != 1 {
			err = fmt.Errorf("wrong password: %v", user.Username)
		}
	default:
		err = fmt.Errorf("wrong password: %v", user.Username)
	}
	return
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
					for key, value := range cm.maps[atomic.LoadInt64(&cm.index)] {
						m[key] = value
					}
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
