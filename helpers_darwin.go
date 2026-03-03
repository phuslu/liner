//go:build darwin

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

type ListenConfig struct {
	FastOpen    bool
	ReusePort   bool // macOS not supported
	DeferAccept bool // macOS not supported
}

func (lc ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	const TCP_FASTOPEN = 0x105 // macOS: /usr/include/netinet/tcp.h

	ln := &net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				if lc.FastOpen {
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
				}
				// ReusePort: macos not supported，skip
				// DeferAccept: macos not supported，skip
			})
		},
	}

	return ln.Listen(ctx, network, address)
}

func (lc ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

type DailerController struct {
	Interface string
}

func (dc DailerController) Control(network, addr string, c syscall.RawConn) (err error) {
	return errors.ErrUnsupported
}

// TCPInfo mirrors the tcp_connection_info struct from macOS <netinet/tcp.h>.
// This is a subset of what Linux exposes; unmapped fields are simply absent.
type TCPInfo struct {
	State               uint8
	Snd_wscale          uint8
	Rcv_wscale          uint8
	_                   uint8
	Options             uint32
	Flags               uint32
	Rto                 uint32
	Maxseg              uint32
	Snd_ssthresh        uint32
	Snd_cwnd            uint32
	Snd_wnd             uint32
	Snd_sbbytes         uint32
	Rcv_wnd             uint32
	Rttcur              uint32
	Srtt                uint32
	Rttvar              uint32
	_                   [4]byte
	Txpackets           uint64
	Txbytes             uint64
	Txretransmitbytes   uint64
	Rxpackets           uint64
	Rxbytes             uint64
	Rxoutoforderbytes   uint64
	Txretransmitpackets uint64
}

func (ops ConnOps) GetTcpInfo() (tcpinfo *TCPInfo, err error) {
	const (
		// TCP_INFO is not exported by the darwin syscall package but the kernel supports it.
		// Value from /usr/include/netinet/tcp.h
		TCP_INFO = 0x200
	)

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
		size := uint32(unsafe.Sizeof(info))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_TCP),
			uintptr(TCP_INFO),
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
	// macOS has no netfilter, so SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST are unavailable.
	// When using pf(4) for transparent proxying, the original destination can be retrieved
	// via getsockname, provided pf is configured with rdr-to or divert-to rules.
	if ops.tc == nil {
		return
	}
	// macOS transparent proxying typically relies on pf + DIOCNATLOOK ioctl to query the NAT table.
	// This is a best-effort fallback using getsockname, valid only under rdr-to scenarios.
	addrport = AddrPortFromNetAddr(ops.tc.LocalAddr())
	if !addrport.IsValid() {
		err = errors.ErrUnsupported
	}
	return
}

func (ops ConnOps) SetTcpCongestion(name string, values ...any) (err error) {
	return errors.ErrUnsupported
}

func (ops ConnOps) SetTcpMaxPacingRate(rate int) error {
	return errors.ErrUnsupported
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

func SetProcessName(name string) error {
	return errors.ErrUnsupported
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
	if err := syscall.Dup2(int(file.Fd()), 1); err != nil {
		return err
	}
	if err := syscall.Dup2(int(file.Fd()), 2); err != nil {
		return err
	}
	return nil
}

func ReadHTTPHeader(conn *net.TCPConn) ([]byte, *net.TCPConn, error) {
	return nil, conn, errors.ErrUnsupported
}

func AppendSetSidToSysProcAttr(old *syscall.SysProcAttr, uid, gid int) *syscall.SysProcAttr {
	return old
}
