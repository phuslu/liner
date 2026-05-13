//go:build android

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ConnProcessInfo struct {
	ID   uint64
	Name string
	Path string
}

func GetTCPConnProcessInfo(conn net.Conn) (ConnProcessInfo, error) {
	return getAndroidConnProcessInfo(conn, syscall.IPPROTO_TCP)
}

func GetUDPConnProcessInfo(conn net.Conn) (ConnProcessInfo, error) {
	return getAndroidConnProcessInfo(conn, syscall.IPPROTO_UDP)
}

func getAndroidConnProcessInfo(conn net.Conn, protocol uint8) (ConnProcessInfo, error) {
	if conn == nil {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}
	finder, ok := newAndroidProcessFinder(conn, protocol)
	if !ok {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}
	uid, err := finder.findUID()
	if err != nil {
		return ConnProcessInfo{}, err
	}
	// Android sock_diag reports UID; package names require a platform package manager.
	return ConnProcessInfo{ID: uint64(uid)}, nil
}

type androidProcessFinder struct {
	source   netip.AddrPort
	family   int
	protocol uint8
}

func newAndroidProcessFinder(conn net.Conn, protocol uint8) (androidProcessFinder, bool) {
	finder := androidProcessFinder{
		family:   unix.AF_INET,
		protocol: protocol,
	}
	finder.source = finder.addrPort(AddrPortFromNetAddr(conn.RemoteAddr()))
	if !finder.source.IsValid() {
		return androidProcessFinder{}, false
	}
	if finder.source.Addr().Is6() {
		finder.family = unix.AF_INET6
	}
	return finder, true
}

func (finder androidProcessFinder) addrPort(addrport netip.AddrPort) netip.AddrPort {
	if !addrport.IsValid() {
		return addrport
	}
	return netip.AddrPortFrom(addrport.Addr().Unmap(), addrport.Port())
}

func (finder androidProcessFinder) findUID() (uint32, error) {
	const inetDiagRequestSize = 56

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	data := make([]byte, unix.SizeofNlMsghdr+inetDiagRequestSize)
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&data[0]))
	hdr.Len = uint32(len(data))
	hdr.Type = unix.SOCK_DIAG_BY_FAMILY
	hdr.Flags = unix.NLM_F_REQUEST | unix.NLM_F_DUMP
	hdr.Seq = 1

	req := data[unix.SizeofNlMsghdr:]
	req[0] = uint8(finder.family)
	req[1] = finder.protocol
	binary.NativeEndian.PutUint32(req[4:8], ^uint32(0))
	binary.BigEndian.PutUint16(req[8:10], finder.source.Port())
	if finder.family == unix.AF_INET6 {
		copy(req[12:28], finder.source.Addr().AsSlice())
	} else {
		copy(req[12:16], finder.source.Addr().AsSlice())
	}
	binary.NativeEndian.PutUint64(req[48:56], ^uint64(0))

	if err = unix.Sendto(fd, data, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, err
	}

	reply := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, reply, 0)
		if err != nil {
			return 0, err
		}
		for remain := reply[:n]; len(remain) >= unix.SizeofNlMsghdr; {
			h := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))
			if h.Len < unix.SizeofNlMsghdr || int(h.Len) > len(remain) {
				return 0, unix.EINVAL
			}
			payload := remain[unix.SizeofNlMsghdr:h.Len]
			switch h.Type {
			case unix.NLMSG_DONE:
				return 0, os.ErrNotExist
			case unix.NLMSG_ERROR:
				if int(h.Len) < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
					return 0, unix.EINVAL
				}
				e := *(*unix.NlMsgerr)(unsafe.Pointer(&payload[0]))
				if e.Error == 0 {
					return 0, os.ErrNotExist
				}
				errno := unix.Errno(-e.Error)
				if errno == unix.ENOENT || errno == unix.ESRCH {
					return 0, os.ErrNotExist
				}
				return 0, errno
			default:
				if uid, ok := finder.parseInetDiagMsg(payload); ok {
					return uid, nil
				}
			}

			step := (int(h.Len) + unix.NLMSG_ALIGNTO - 1) & ^(unix.NLMSG_ALIGNTO - 1)
			if step > len(remain) {
				step = len(remain)
			}
			remain = remain[step:]
		}
	}
}

func (finder androidProcessFinder) parseInetDiagMsg(payload []byte) (uint32, bool) {
	const inetDiagResponseMinSize = 72

	if len(payload) < inetDiagResponseMinSize {
		return 0, false
	}
	srcPort := binary.BigEndian.Uint16(payload[4:6])
	var src netip.Addr
	switch finder.family {
	case unix.AF_INET:
		var a [4]byte
		copy(a[:], payload[8:12])
		src = netip.AddrFrom4(a)
	case unix.AF_INET6:
		var a [16]byte
		copy(a[:], payload[8:24])
		src = netip.AddrFrom16(a).Unmap()
	default:
		return 0, false
	}
	if netip.AddrPortFrom(src, srcPort) != finder.source {
		return 0, false
	}
	inode := binary.NativeEndian.Uint32(payload[68:72])
	if inode == 0 {
		return 0, false
	}
	return binary.NativeEndian.Uint32(payload[64:68]), true
}
