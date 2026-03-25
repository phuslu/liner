//go:build windows

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ = fmt.Printf // for debugging log

type ListenConfig struct {
	ReusePort   bool
	FastOpen    bool
	DeferAccept bool
}

func (ln ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func (ln ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	laddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	return net.ListenUDP(network, laddr)
}

type DailerController struct {
	Interface string
}

func (dc DailerController) Control(network, address string, c syscall.RawConn) (err error) {
	if dc.Interface == "" {
		return nil
	}

	if ip, _ := netip.ParseAddr(dc.Interface); ip.IsValid() {
		var controlErr error
		if err = c.Control(func(fd uintptr) {
			controlErr = dc.bindHandleToIP(windows.Handle(fd), ip)
		}); err != nil {
			return err
		}
		return controlErr
	}

	var controlErr error
	if err = c.Control(func(fd uintptr) {
		controlErr = dc.bindHandleToInterface(windows.Handle(fd), network, address)
	}); err != nil {
		return err
	}
	return controlErr
}

func (dc DailerController) bindHandleToIP(handle windows.Handle, ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("invalid ip address")
	}
	var sa windows.Sockaddr
	switch {
	case ip.Is4() || ip.Is4In6():
		v4 := ip
		if v4.Is4In6() {
			v4 = v4.Unmap()
		}
		addr := v4.As4()
		sa = &windows.SockaddrInet4{Addr: addr}
	case ip.Is6():
		addr := ip.As16()
		sa6 := &windows.SockaddrInet6{}
		sa6.Addr = addr
		sa = sa6
	default:
		return errors.New("unsupported ip address family")
	}
	if err := windows.Bind(handle, sa); err != nil {
		return os.NewSyscallError("bind", err)
	}
	return nil
}

func (dc DailerController) bindHandleToInterface(handle windows.Handle, network, address string) error {
	name := strings.TrimSpace(dc.Interface)
	if name == "" {
		return errors.New("empty interface name")
	}
	size := uint32(15 * 1024)
	var ipv4Idx, ipv6Idx uint32
	for {
		buf := make([]byte, size)
		adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, adapter, &size)
		if err == nil {
			for aa := adapter; aa != nil; aa = aa.Next {
				friendly := windows.UTF16PtrToString(aa.FriendlyName)
				adapterName := windows.BytePtrToString(aa.AdapterName)
				if strings.EqualFold(name, friendly) || strings.EqualFold(name, adapterName) {
					ipv4Idx = aa.IfIndex
					ipv6Idx = aa.Ipv6IfIndex
					if ipv4Idx == 0 {
						ipv4Idx = ipv6Idx
					}
					if ipv6Idx == 0 {
						ipv6Idx = ipv4Idx
					}
					if ipv4Idx == 0 && ipv6Idx == 0 {
						return fmt.Errorf("interface %s has no usable index", dc.Interface)
					}
					goto indicesReady
				}
			}
			return fmt.Errorf("network interface not found: %s", dc.Interface)
		}
		if err != syscall.ERROR_BUFFER_OVERFLOW {
			return os.NewSyscallError("GetAdaptersAddresses", err)
		}
	}

indicesReady:
	family := byte(0)
	switch strings.ToLower(network) {
	case "tcp4", "udp4":
		family = 4
	case "tcp6", "udp6":
		family = 6
	default:
		host, _, err := net.SplitHostPort(address)
		if err == nil {
			if addr, perr := netip.ParseAddr(host); perr == nil {
				if addr.Is6() && !addr.Is4In6() {
					family = 6
				} else {
					family = 4
				}
			}
		}
	}

	const (
		IP_UNICAST_IF   = 31
		IPV6_UNICAST_IF = 31
	)

	setIPv4 := family != 6 && ipv4Idx != 0
	setIPv6 := family != 4 && ipv6Idx != 0
	if setIPv4 {
		if err := windows.SetsockoptInt(handle, int(syscall.IPPROTO_IP), IP_UNICAST_IF, int(ipv4Idx)); err != nil {
			switch err {
			case windows.WSAEINVAL, windows.WSAENOPROTOOPT, windows.WSAEFAULT:
				// ignored; OS doesn't support the option for this socket
			default:
				return os.NewSyscallError("setsockopt IP_UNICAST_IF", err)
			}
		}
	}
	if setIPv6 {
		if err := windows.SetsockoptInt(handle, int(windows.IPPROTO_IPV6), IPV6_UNICAST_IF, int(ipv6Idx)); err != nil {
			switch err {
			case windows.WSAEINVAL, windows.WSAENOPROTOOPT, windows.WSAEFAULT:
				// ignored; OS doesn't support the option for this socket
			default:
				return os.NewSyscallError("setsockopt IPV6_UNICAST_IF", err)
			}
		}
	}
	if !setIPv4 && !setIPv6 {
		return errors.New("no interface index available for requested family")
	}
	return nil
}

// TCPInfo mirrors the TCP_INFO_v0 structure that SIO_TCP_INFO returns on
// Windows. Only commonly used counters are exposed so templates can inspect
// basic congestion and RTT data similar to other platforms.
type TCPInfo struct {
	State             uint32  // TCPSTATE (通常是 enum -> ULONG)
	Mss               uint32  // ULONG
	ConnectionTimeMs  uint64  // ULONG64
	TimestampsEnabled uint8   // BOOLEAN (UCHAR)
	_                 [3]byte // padding 对齐到 4 字节

	RttUs         uint32 // ULONG
	MinRttUs      uint32 // ULONG
	BytesInFlight uint32 // ULONG
	Cwnd          uint32 // ULONG
	SndWnd        uint32 // ULONG
	RcvWnd        uint32 // ULONG
	RcvBuf        uint32 // ULONG

	BytesOut uint64 // ULONG64
	BytesIn  uint64 // ULONG64

	BytesReordered  uint32 // ULONG
	BytesRetrans    uint32 // ULONG
	FastRetrans     uint32 // ULONG
	DupAcksIn       uint32 // ULONG
	TimeoutEpisodes uint32 // ULONG

	SynRetrans uint8   // UCHAR
	_          [3]byte // padding (结构体对齐)
}

func (ops ConnOps) GetTcpInfo() (tcpinfo *TCPInfo, err error) {
	if ops.tc == nil || ops.tc.RemoteAddr() == nil {
		return
	}

	const SIO_TCP_INFO uint32 = windows.IOC_INOUT | windows.IOC_VENDOR | 39

	var c syscall.RawConn
	c, err = ops.tc.SyscallConn()
	if err != nil {
		return
	}
	err = c.Control(func(fd uintptr) {
		var info TCPInfo
		var version uint32 = 0 // TCP_INFO_v0
		var bytesReturned uint32
		errno := windows.WSAIoctl(
			windows.Handle(fd),
			SIO_TCP_INFO,
			(*byte)(unsafe.Pointer(&version)),
			uint32(unsafe.Sizeof(version)),
			(*byte)(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
			&bytesReturned,
			nil,
			0,
		)
		if errno != nil {
			err = os.NewSyscallError("WSAIoctl SIO_TCP_INFO", errno)
			return
		}
		tcpinfo = &info
	})
	return
}

func (ops ConnOps) GetOriginalDST() (addrport netip.AddrPort, err error) {
	return netip.AddrPort{}, errors.ErrUnsupported
}

func (ops ConnOps) SetTcpCongestion(name string, values ...any) (err error) {
	if ops.tc == nil {
		return errors.ErrUnsupported
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("empty congestion algorithm")
	}
	alg, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	var c syscall.RawConn
	c, err = ops.tc.SyscallConn()
	if err != nil {
		return err
	}
	err = c.Control(func(fd uintptr) {
		sz := int32(len(alg) * int(unsafe.Sizeof(alg[0])))
		if sz == 0 {
			err = errors.New("invalid congestion algorithm buffer")
			return
		}
		b := (*byte)(unsafe.Pointer(&alg[0]))
		err = windows.Setsockopt(
			windows.Handle(fd),
			int32(syscall.IPPROTO_TCP),
			int32(windows.TCP_CONGESTION_ALGORITHM),
			b,
			sz,
		)
		if err != nil {
			err = os.NewSyscallError("setsockopt IPPROTO_TCP TCP_CONGESTION_ALGORITHM "+name, err)
		}
	})
	return
}

func (ops ConnOps) SetTcpMaxPacingRate(rate int) error {
	return errors.ErrUnsupported
}

func SetTermWindowSize(fd uintptr, width, height uint16) error {
	return windows.ResizePseudoConsole(windows.Handle(fd), windows.Coord{
		X: int16(width),
		Y: int16(height),
	})
}

func SetProcessName(name string) error {
	return errors.ErrUnsupported
}

func KillPid(pid int, sig syscall.Signal) error {
	if sig != syscall.SIGTERM {
		return errors.ErrUnsupported
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func RedirectOutputToFile(filename string) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	h := windows.Handle(file.Fd())

	if err := windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, h); err != nil {
		return err
	}

	if err := windows.SetStdHandle(windows.STD_ERROR_HANDLE, h); err != nil {
		return err
	}

	// sync to Go runtime
	os.Stdout = file
	os.Stderr = file

	return nil
}

func AppendSetSidToSysProcAttr(old *syscall.SysProcAttr, uid, gid int) *syscall.SysProcAttr {
	if old == nil {
		old = &syscall.SysProcAttr{}
	}

	spa := *old
	spa.CreationFlags |= syscall.CREATE_NEW_PROCESS_GROUP

	return &spa
}

func EnableVirtualTerminalSequences() error {
	enable := func(stdHandle uint32, mask uint32) error {
		handle, err := windows.GetStdHandle(stdHandle)
		if err != nil || handle == windows.InvalidHandle {
			return err
		}
		var mode uint32
		if err := windows.GetConsoleMode(handle, &mode); err != nil {
			return err
		}
		if mode&mask == mask {
			return err
		}
		return windows.SetConsoleMode(handle, mode|mask)
	}

	return cmp.Or(
		enable(windows.STD_OUTPUT_HANDLE, windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING),
		enable(windows.STD_ERROR_HANDLE, windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING),
		enable(windows.STD_INPUT_HANDLE, windows.ENABLE_VIRTUAL_TERMINAL_INPUT),
	)
}
