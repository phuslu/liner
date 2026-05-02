//go:build linux

package main

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
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

	if ip := AddrPortFromNetAddr(ops.tc.LocalAddr()).Addr(); ip.Is6() && !ip.Is4In6() {
		err = c.Control(func(fd uintptr) {
			const IP6T_SO_ORIGINAL_DST = 80 // Linux netfilter original destination
			var sa syscall.RawSockaddrInet6
			size := uint32(unsafe.Sizeof(sa))
			_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(syscall.SOL_IP), uintptr(IP6T_SO_ORIGINAL_DST), uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)), 0)
			if errno != 0 {
				err = errno
				return
			}
			port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&sa.Port))[:])
			addrport = netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), port)
		})
	} else {
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
	}

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

	argv0 := unsafe.Slice(unsafe.StringData(os.Args[0]), n)

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

func ConfigureTunInterface(name string, addressPrefix, routePrefix netip.Prefix, metric int) error {
	if !addressPrefix.Addr().Is4() || routePrefix.IsValid() && !routePrefix.Addr().Is4() {
		return errors.ErrUnsupported
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}

	attr := func(typ uint16, data []byte) []byte {
		n := unix.SizeofRtAttr + len(data)
		b := make([]byte, (n+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1))
		rtattr := (*unix.RtAttr)(unsafe.Pointer(&b[0]))
		rtattr.Len = uint16(n)
		rtattr.Type = typ
		copy(b[unix.SizeofRtAttr:], data)
		return b
	}
	uint32attr := func(typ uint16, value uint32) []byte {
		var b [4]byte
		binary.NativeEndian.PutUint32(b[:], value)
		return attr(typ, b[:])
	}
	update := func(typ, flags uint16, data []byte, attrs ...[]byte) error {
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
		if err != nil {
			return err
		}
		defer unix.Close(fd)

		n := unix.SizeofNlMsghdr + len(data)
		for _, attr := range attrs {
			n += len(attr)
		}
		b := make([]byte, n)
		hdr := (*unix.NlMsghdr)(unsafe.Pointer(&b[0]))
		hdr.Len = uint32(len(b))
		hdr.Type = typ
		hdr.Flags = unix.NLM_F_REQUEST | flags
		hdr.Seq = 1

		off := unix.SizeofNlMsghdr
		off += copy(b[off:], data)
		for _, attr := range attrs {
			off += copy(b[off:], attr)
		}
		if err = unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			return err
		}

		reply := make([]byte, 8192)
		for {
			n, _, err = unix.Recvfrom(fd, reply, 0)
			if err != nil {
				return err
			}
			for remain := reply[:n]; len(remain) >= unix.SizeofNlMsghdr; {
				h := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))
				if h.Len < unix.SizeofNlMsghdr || int(h.Len) > len(remain) {
					return unix.EINVAL
				}
				if h.Type == unix.NLMSG_ERROR {
					if int(h.Len) < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
						return unix.EINVAL
					}
					e := *(*unix.NlMsgerr)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
					if e.Error == 0 {
						return nil
					}
					return unix.Errno(-e.Error)
				}
				if h.Type == unix.NLMSG_DONE {
					return nil
				}
				step := (int(h.Len) + unix.NLMSG_ALIGNTO - 1) & ^(unix.NLMSG_ALIGNTO - 1)
				if step > len(remain) {
					step = len(remain)
				}
				remain = remain[step:]
			}
		}
	}

	ip4 := addressPrefix.Addr().As4()
	addrmsg := unix.IfAddrmsg{
		Family:    unix.AF_INET,
		Prefixlen: uint8(addressPrefix.Bits()),
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Index:     uint32(iface.Index),
	}
	err = update(unix.RTM_NEWADDR, unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE, unsafe.Slice((*byte)(unsafe.Pointer(&addrmsg)), unix.SizeofIfAddrmsg),
		attr(unix.IFA_LOCAL, ip4[:]),
		attr(unix.IFA_ADDRESS, ip4[:]),
	)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("set tun address: %w", err)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("set tun link up: %w", err)
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("set tun link up: %w", err)
	}
	if err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("set tun link up: %w", err)
	}
	if flags := ifr.Uint16(); flags&uint16(unix.IFF_UP) == 0 {
		ifr.SetUint16(flags | uint16(unix.IFF_UP))
		if err = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
			return fmt.Errorf("set tun link up: %w", err)
		}
	}

	if routePrefix.IsValid() {
		routePrefix = routePrefix.Masked()
		rmsg := unix.RtMsg{
			Family:   unix.AF_INET,
			Dst_len:  uint8(routePrefix.Bits()),
			Table:    unix.RT_TABLE_MAIN,
			Protocol: unix.RTPROT_STATIC,
			Scope:    unix.RT_SCOPE_LINK,
			Type:     unix.RTN_UNICAST,
		}
		attrs := [][]byte{uint32attr(unix.RTA_OIF, uint32(iface.Index))}
		if metric > 0 {
			attrs = append(attrs, uint32attr(unix.RTA_PRIORITY, uint32(metric)))
		}
		if routePrefix.Bits() > 0 {
			ip4 = routePrefix.Addr().As4()
			attrs = append(attrs, attr(unix.RTA_DST, ip4[:]))
		}
		err = update(unix.RTM_NEWROUTE, unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL, unsafe.Slice((*byte)(unsafe.Pointer(&rmsg)), unix.SizeofRtMsg), attrs...)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("set tun route: %w", err)
		}
	}

	return nil
}

func AppendSetSidToSysProcAttr(old *syscall.SysProcAttr, uid, gid int) *syscall.SysProcAttr {
	if caps, _ := getcap(); !caps.SetUID || !caps.SetGID {
		return old
	}

	spa := *old
	spa.Setsid = true
	spa.Setctty = true
	spa.Ctty = 0
	spa.Credential = &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
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

func EnableVirtualTerminalSequences() error {
	return nil
}
