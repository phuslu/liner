package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
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
	"github.com/nathanaelle/password/v2"
	"github.com/phuslu/lru"
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

func ReadFile(s string) (body []byte, err error) {
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

var htpassdCache = lru.NewTTLCache[string, [][2]string](1024)

func HtpasswdVerify(htpasswdFile string, req *http.Request) error {
	loader := func(ctx context.Context, filename string) ([][2]string, time.Duration, error) {
		result := make([][2]string, 0, 64)

		file, err := os.Open(htpasswdFile)
		if err != nil {
			return nil, 0, fmt.Errorf("open htpasswd file %s error: %w", htpasswdFile, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			parts := strings.SplitN(scanner.Text(), ":", 2)
			if len(parts) != 2 {
				continue
			}
			result = append(result, [2]string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])})
		}
		if err := scanner.Err(); err != nil {
			return nil, 0, fmt.Errorf("read htpasswd file %s error: %w", htpasswdFile, err)
		}

		return result, 2 * time.Minute, nil
	}

	pairs, err, _ := htpassdCache.GetOrLoad(req.Context(), htpasswdFile, loader)
	if err != nil {
		return err
	}

	s := req.Header.Get("authorization")
	if s == "" {
		return errors.New("no authorization header")
	}
	if !strings.HasPrefix(s, "Basic ") {
		return fmt.Errorf("unsupported authorization header: %+v", s)
	}
	data, err := base64.StdEncoding.DecodeString(s[6:])
	if err != nil {
		return fmt.Errorf("invalid authorization header: %+v", s)
	}
	parts := strings.SplitN(string(data), ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid authorization header: %+v", s)
	}
	user, pass := parts[0], parts[1]

	factory := &password.Factory{}
	factory.Register(password.MD5, password.SHA256, password.SHA512, password.BCRYPT)

	for _, pair := range pairs {
		if user == parts[0] {
			factory.Set(pair[1])
			if factory.CrypterFound().Verify(s2b(pass)) {
				return nil
			} else {
				return fmt.Errorf("wrong username or password: %+v", parts)
			}
		}
	}

	return fmt.Errorf("wrong username or password: %+v", parts)
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
