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

type TCPInfo struct{}

func (ops ConnOps) GetTcpInfo() (*TCPInfo, error) {
	return nil, errors.ErrUnsupported
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

func ReadHTTPHeader(conn *net.TCPConn) ([]byte, *net.TCPConn, error) {
	return nil, conn, errors.ErrUnsupported
}

func AppendSetSidToSysProcAttr(old *syscall.SysProcAttr, uid, gid int) *syscall.SysProcAttr {
	return old
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
