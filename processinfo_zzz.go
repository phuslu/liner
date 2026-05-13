//go:build !darwin && !linux && !windows

package main

import (
	"errors"
	"net"
)

type ConnProcessInfo struct {
	ID   uint64
	Name string
	Path string
}

func GetTCPConnProcessInfo(conn net.Conn) (ConnProcessInfo, error) {
	return ConnProcessInfo{}, errors.ErrUnsupported
}

func GetUDPConnProcessInfo(conn net.Conn) (ConnProcessInfo, error) {
	return ConnProcessInfo{}, errors.ErrUnsupported
}
