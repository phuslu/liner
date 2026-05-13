//go:build !darwin && !linux && !windows

package main

import (
	"errors"
	"net"
)

type TCPConnProcessInfo struct {
	ID   uint64
	Name string
	Path string
}

func GetTCPConnProcessInfo(conn net.Conn) (TCPConnProcessInfo, error) {
	return TCPConnProcessInfo{}, errors.ErrUnsupported
}

func GetUDPConnProcessInfo(conn net.Conn) (TCPConnProcessInfo, error) {
	return TCPConnProcessInfo{}, errors.ErrUnsupported
}
