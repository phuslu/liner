//go:build !linux
// +build !linux

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
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
	return errors.ErrUnsupported
}

func SetProcessName(name string) error {
	return errors.ErrUnsupported
}

func KillPid(pid int, sig syscall.Signal) error {
	return errors.ErrUnsupported
}

func RedirectOutputToFile(filename string) error {
	return errors.ErrUnsupported
}

func ReadHTTPHeader(conn *net.TCPConn) ([]byte, *net.TCPConn, error) {
	return nil, conn, errors.ErrUnsupported
}

func (ops ConnOps) PeekTLSClientHelloServerName() (serverName string, header []byte, err error) {
	return "", nil, errors.ErrUnsupported
}

func AppendSetSidToSysProcAttr(old *syscall.SysProcAttr) *syscall.SysProcAttr {
	return old
}
