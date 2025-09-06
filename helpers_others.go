//go:build !linux
// +build !linux

package main

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
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

type TCPConn struct {
	tc *net.TCPConn
}

type TCPInfo struct {
	RTT time.Duration
}

func (c *TCPConn) GetTcpInfo() (TCPInfo, error) {
	return TCPInfo{}, nil
}

func (tc *TCPConn) SetTcpCongestion(name string, values ...any) error {
	return nil
}

func (tc *TCPConn) SetTcpMaxPacingRate(rate int) (err error) {
	return nil
}

func SetTermWindowSize(fd uintptr, width, height uint16) error {
	return nil
}

func SetProcessName(name string) error {
	return nil
}

func KillPid(pid int, sig syscall.Signal) error {
	return nil
}

func ReadHTTPHeader(conn *net.TCPConn) ([]byte, *net.TCPConn, error) {
	return nil, conn, errors.New("not implemented")
}
