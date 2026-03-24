//go:build windows

package main

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

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

func (dc DailerController) Control(network, address string, c syscall.RawConn) error {
	return nil
}

// TCPInfo mirrors the TCP_INFO_v0 structure that SIO_TCP_INFO returns on
// Windows. Only commonly used counters are exposed so templates can inspect
// basic congestion and RTT data similar to other platforms.
type TCPInfo struct {
	State            uint32
	Mss              uint32
	ConnectionTimeMs uint64
	BytesInFlight    uint64
	Cwnd             uint32
	SndWnd           uint32
	RcvWnd           uint32
	RttUs            uint32
	MinRttUs         uint32
	BytesOut         uint32
	BytesIn          uint32
	BytesReordered   uint32
	BytesRetrans     uint32
	FastRetrans      uint32
	DupAcksIn        uint32
	TimeoutEpisodes  uint32
	SynRetransCount  uint8
	Flags            uint8
	_                uint16
}

func (ops ConnOps) GetTcpInfo() (tcpinfo *TCPInfo, err error) {
	if ops.tc == nil {
		return
	}

	const (
		// _WSAIOW(IOC_VENDOR, 39)
		sioTcpInfo       uint32 = 0x98000027
		tcpInfoVersionV0 uint32 = 0
	)

	var c syscall.RawConn
	c, err = ops.tc.SyscallConn()
	if err != nil {
		return
	}
	err = c.Control(func(fd uintptr) {
		var info TCPInfo
		version := tcpInfoVersionV0
		var bytesReturned uint32
		errno := windows.WSAIoctl(
			windows.Handle(fd),
			sioTcpInfo,
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

func (ops ConnOps) SetTcpCongestion(name string, values ...any) error {
	return errors.ErrUnsupported
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
