//go:build linux
// +build linux

package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type ListenConfig struct {
	ReusePort   bool
	FastOpen    bool
	DeferAccept bool
}

func (lc ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	const SO_REUSEPORT = 15
	const TCP_FASTOPEN = 23
	ln := &net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				if lc.ReusePort {
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
				}
				if lc.FastOpen {
					syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, TCP_FASTOPEN, 16*1024)
				}
				if lc.DeferAccept {
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT, 1)
				}
			})
		},
	}

	return ln.Listen(ctx, network, address)
}

func (lc ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	const SO_REUSEPORT = 15
	ln := &net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				if lc.ReusePort {
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
				}
			})
		},
	}

	return ln.ListenPacket(ctx, network, address)
}

type DailerController struct {
	Interface string
}

func (dc DailerController) Control(network, addr string, c syscall.RawConn) (err error) {
	c.Control(func(fd uintptr) {
		if ip, _ := netip.ParseAddr(dc.Interface); ip.IsValid() {
			var sa syscall.Sockaddr
			if ip.Is4() {
				ip4 := ip.As4()
				sa = &syscall.SockaddrInet4{
					Addr: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]},
				}
			} else {
				ip6 := ip.As16()
				sa = &syscall.SockaddrInet6{
					Addr: [16]byte{
						ip6[0], ip6[1], ip6[2], ip6[3],
						ip6[4], ip6[5], ip6[6], ip6[7],
						ip6[8], ip6[9], ip6[10], ip6[11],
						ip6[12], ip6[13], ip6[14], ip6[15],
					},
				}
			}
			const IP_BIND_ADDRESS_NO_PORT = 24
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1)
			if err != nil {
				return
			}
			err = syscall.Bind(int(fd), sa)
		} else if dc.Interface != "" {
			err = syscall.BindToDevice(int(fd), dc.Interface)
		}
	})
	return
}

type TCPInfo syscall.TCPInfo

func (ops ConnOps) GetTcpInfo() (tcpinfo *TCPInfo, err error) {
	if ops.tc == nil {
		return
	}
	var c syscall.RawConn
	c, err = ops.tc.SyscallConn()
	if err != nil {
		return
	}
	err = c.Control(func(fd uintptr) {
		var info TCPInfo
		var size uint32 = syscall.SizeofTCPInfo
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_TCP),
			uintptr(syscall.TCP_INFO),
			uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			err = errno
		} else {
			tcpinfo = &info
		}
	})
	return
}

func (ops ConnOps) GetOriginalDST() (addrport netip.AddrPort, err error) {
	if ops.tc == nil {
		return
	}
	var c syscall.RawConn
	c, err = ops.tc.SyscallConn()
	if err != nil {
		return
	}

	err = c.Control(func(fd uintptr) {
		const SO_ORIGINAL_DST = 80 // Linux netfilter original destination
		var sa syscall.RawSockaddrInet4
		size := uint32(unsafe.Sizeof(sa))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(syscall.SOL_IP), uintptr(SO_ORIGINAL_DST), uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			err = errno
			return
		}
		port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
		addrport = netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port)
	})

	return
}

//go:linkname setsockopt syscall.setsockopt
func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)

func intof(n any) int {
	switch n := n.(type) {
	case int:
		return int(n)
	case int8:
		return int(n)
	case int16:
		return int(n)
	case int32:
		return int(n)
	case int64:
		return int(n)
	case uint:
		return int(n)
	case uint8:
		return int(n)
	case uint16:
		return int(n)
	case uint32:
		return int(n)
	case uint64:
		return int(n)
	case uintptr:
		return int(n)
	}
	return 0
}

func (ops ConnOps) SetTcpCongestion(name string, values ...any) (err error) {
	if ops.tc == nil {
		err = errors.ErrUnsupported
		return
	}
	var c syscall.RawConn
	c, err = ops.tc.SyscallConn()
	if err != nil {
		return
	}
	c.Control(func(fd uintptr) {
		err = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, name)
		if err != nil {
			err = os.NewSyscallError("setsockopt IPPROTO_TCP TCP_CONGESTION brutal", err)
		}
		switch name {
		case "brutal":
			params := struct {
				Rate     uint64
				CwndGain uint32
			}{
				Rate:     uint64(intof(values[0])),
				CwndGain: uint32(cmp.Or(intof(values[1]), 20)), // 20, hysteria2 default
			}
			const TCP_BRUTAL_PARAMS = 23301
			err = setsockopt(int(fd), syscall.IPPROTO_TCP, TCP_BRUTAL_PARAMS, unsafe.Pointer(&params), unsafe.Sizeof(params))
			if err != nil {
				err = os.NewSyscallError("setsockopt IPPROTO_TCP TCP_BRUTAL_PARAMS", err)
			}
		}
	})
	return
}

func (ops ConnOps) SetTcpMaxPacingRate(rate int) (err error) {
	if ops.tc == nil {
		err = errors.ErrUnsupported
		return
	}
	const SO_MAX_PACING_RATE = 47
	var c syscall.RawConn
	c, err = ops.tc.SyscallConn()
	if err != nil {
		return
	}
	c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_MAX_PACING_RATE, rate)
		if err != nil {
			err = os.NewSyscallError("setsockopt SOL_SOCKET SO_MAX_PACING_RATE "+strconv.Itoa(rate), err)
		}
	})
	return
}

func SetTermWindowSize(fd uintptr, width, height uint16) error {
	ws := &struct {
		Height uint16
		Width  uint16
		x      uint16 // unused
		y      uint16 // unused
	}{
		Width:  width,
		Height: height,
	}

	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))

	return nil
}

func KillPid(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

func RedirectOutputToFile(filename string) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := syscall.Dup3(int(file.Fd()), 1, 0); err != nil {
		return err
	}
	if err := syscall.Dup3(int(file.Fd()), 2, 0); err != nil {
		return err
	}
	return nil
}

func SetProcessName(name string) error {
	n := -1
	for _, arg := range os.Args {
		n += len(arg) + 1
	}
	if n < len(name) {
		name = name[:n]
	}

	argv0str := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0]))
	argv0 := unsafe.Slice((*byte)(unsafe.Pointer(argv0str.Data)), n)

	n = copy(argv0, name+strings.Repeat("\x00", n+1-len(name)))
	if n < len(argv0) {
		argv0[n] = 0
	}

	if n := strings.LastIndexByte(name, '/'); n > 0 {
		name = name[n+1:]
	}

	err := os.WriteFile("/proc/"+strconv.Itoa(os.Getpid())+"/comm", []byte(name), 0644)

	return err
}

func ReadHTTPHeader(tc *net.TCPConn) ([]byte, *net.TCPConn, error) {
	f, err := tc.File()
	if err != nil {
		return nil, tc, err
	}

	b := make([]byte, os.Getpagesize())
	n, _, err := syscall.Recvfrom(int(f.Fd()), b, syscall.MSG_PEEK)
	if err != nil {
		return nil, tc, err
	}

	if n == 0 {
		return nil, tc, io.EOF
	}

	if b[0] < 'A' || b[0] > 'Z' {
		return nil, tc, io.EOF
	}

	n = bytes.Index(b, []byte{'\r', '\n', '\r', '\n'})
	if n < 0 {
		return nil, tc, io.EOF
	}

	b = b[:n+4]
	n, err = tc.Read(b)

	return b, tc, err
}

// PeekTLSClientHelloServerName 从 TCP 连接中 peek 读取 TLS ClientHello 的 SNI 名称。
// 使用 MSG_PEEK 系统调用，不消耗连接数据流。
// 返回 SNI 名称和 peek 到的原始数据。
func (ops ConnOps) PeekTLSClientHelloServerName() (serverName string, header []byte, err error) {
	if ops.tc == nil {
		return "", nil, errors.ErrUnsupported
	}

	f, err := ops.tc.File()
	if err != nil {
		return "", nil, err
	}
	defer f.Close()

	b := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(int(f.Fd()), b, syscall.MSG_PEEK)
	if err != nil {
		return "", nil, err
	}

	if n < 5 {
		return "", nil, io.EOF
	}

	// 检查是否是 TLS 握手记录 (ContentType = 0x16)
	if b[0] != 0x16 {
		return "", nil, io.EOF
	}

	// TLS 记录头: ContentType(1) + Version(2) + Length(2)
	recordLen := int(binary.BigEndian.Uint16(b[3:5]))
	if n < 5+recordLen {
		// 数据不完整，尝试获取更多
		if recordLen > len(b)-5 {
			recordLen = len(b) - 5
		}
	}

	// 解析 ClientHello 获取 SNI
	serverName = parseTLSClientHelloSNI(b[5 : 5+min(recordLen, n-5)])

	header = b[:n]
	return serverName, header, nil
}

// parseTLSClientHelloSNI 从 TLS ClientHello 消息中解析 SNI 扩展获取服务器名称
func parseTLSClientHelloSNI(data []byte) string {
	if len(data) < 38 {
		return ""
	}

	// HandshakeType (1 byte) 必须是 ClientHello (0x01)
	if data[0] != 0x01 {
		return ""
	}

	// Length (3 bytes)
	handshakeLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+handshakeLen {
		handshakeLen = len(data) - 4
	}

	pos := 4

	// ClientVersion (2 bytes) + Random (32 bytes)
	pos += 2 + 32
	if pos >= len(data) {
		return ""
	}

	// SessionID Length (1 byte) + SessionID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return ""
	}

	// CipherSuites Length (2 bytes) + CipherSuites
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > len(data) {
		return ""
	}

	// CompressionMethods Length (1 byte) + CompressionMethods
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen
	if pos+2 > len(data) {
		return ""
	}

	// Extensions Length (2 bytes)
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// 遍历扩展查找 SNI (Type = 0x0000)
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > extensionsEnd {
			break
		}

		// SNI 扩展类型是 0x0000
		if extType == 0x0000 && extLen > 5 {
			// SNI 扩展格式: ListLength(2) + NameType(1) + NameLength(2) + Name
			// sniListLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
			nameType := data[pos+2]
			nameLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
			if nameType == 0 && pos+5+nameLen <= extensionsEnd {
				return string(data[pos+5 : pos+5+nameLen])
			}
		}

		pos += extLen
	}

	return ""
}

func AppendSetSidToSysProcAttr(old *syscall.SysProcAttr) *syscall.SysProcAttr {
	if caps, _ := getcap(); !caps.SetUID || !caps.SetGID {
		return old
	}

	spa := *old
	spa.Setsid = true
	spa.Setctty = true
	spa.Ctty = 0
	spa.Credential = &syscall.Credential{
		Uid: uint32(os.Getuid()),
		Gid: uint32(os.Getgid()),
	}

	return &spa
}

type linuxcapability struct {
	SetUID bool
	SetGID bool
}

func getcap() (caps linuxcapability, err error) {
	// <linux/capability.h>
	const (
		_LINUX_CAPABILITY_VERSION_3 = 0x20080522
		CAP_SETUID                  = 7
		CAP_SETGID                  = 6
	)

	var header struct {
		Version uint32
		Pid     int32
	}

	var data struct {
		Effective   uint32
		Permitted   uint32
		Inheritable uint32
	}

	header.Version = _LINUX_CAPABILITY_VERSION_3
	header.Pid = 0 // 0 = self

	_, _, errno := syscall.Syscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data)), 0)
	if errno != 0 {
		return linuxcapability{}, errno
	}

	caps.SetGID = (data.Effective & (1 << CAP_SETUID)) != 0
	caps.SetGID = (data.Effective & (1 << CAP_SETGID)) != 0

	return caps, nil
}
