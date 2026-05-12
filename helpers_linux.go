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
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
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
			// LocalDialer passes IP bindings through net.Dialer.LocalAddr.
			return
		}
		if dc.Interface != "" {
			err = syscall.BindToDevice(int(fd), dc.Interface)
		}
	})
	return
}

type TCPInfo syscall.TCPInfo

func (tcpinfo *TCPInfo) RTT() time.Duration {
	if tcpinfo == nil || tcpinfo.Rtt == 0 {
		return 0
	}
	return time.Duration(tcpinfo.Rtt) * time.Microsecond
}

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

type ConnProcessInfo struct {
	ProcessName string
	ProcessID   uint64
}

func (ops ConnOps) GetProcessInfo() (ConnProcessInfo, error) {
	if ops.tc == nil {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}
	source := linuxNormalizeAddrPort(AddrPortFromNetAddr(ops.tc.RemoteAddr()))
	destination := linuxNormalizeAddrPort(AddrPortFromNetAddr(ops.tc.LocalAddr()))
	if !source.IsValid() || !destination.IsValid() || source.Addr().BitLen() != destination.Addr().BitLen() {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}

	entry, err := findLinuxConnectionEntry(source, destination)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		if originalDst, originalErr := ops.GetOriginalDST(); originalErr == nil {
			originalDst = linuxNormalizeAddrPort(originalDst)
			if originalDst.IsValid() && originalDst != destination && source.Addr().BitLen() == originalDst.Addr().BitLen() {
				entry, err = findLinuxConnectionEntry(source, originalDst)
			}
		}
	}
	if err != nil {
		return ConnProcessInfo{}, err
	}
	if entry.inode == 0 {
		return ConnProcessInfo{}, os.ErrNotExist
	}
	return linuxProcessInfoFromSocketInode(entry.inode)
}

var (
	linuxIPv4ProcessSnapshotPtr atomic.Pointer[linuxProcessSnapshot]
	linuxIPv6ProcessSnapshotPtr atomic.Pointer[linuxProcessSnapshot]
	linuxIPv4ProcessSnapshotMu  sync.Mutex
	linuxIPv6ProcessSnapshotMu  sync.Mutex
)

type linuxConnEntry struct {
	src   netip.AddrPort
	dst   netip.AddrPort
	inode uint64
}

type linuxProcessSnapshot struct {
	createdAt time.Time
	entries   []linuxConnEntry
}

func findLinuxConnectionEntry(source, destination netip.AddrPort) (linuxConnEntry, error) {
	family := unix.AF_INET
	if source.Addr().Is6() {
		family = unix.AF_INET6
	}
	ptr, mu := linuxProcessSnapshotState(family)
	snapshot := ptr.Load()
	if snapshot.fresh() {
		if entry, ok := snapshot.find(source, destination); ok {
			return entry, nil
		}
		refreshed, err := loadLinuxProcessSnapshot(family, ptr, mu, true, snapshot)
		if err != nil {
			return linuxConnEntry{}, err
		}
		if entry, ok := refreshed.find(source, destination); ok {
			return entry, nil
		}
		return linuxConnEntry{}, os.ErrNotExist
	}

	var err error
	snapshot, err = loadLinuxProcessSnapshot(family, ptr, mu, false, snapshot)
	if err != nil {
		return linuxConnEntry{}, err
	}
	if entry, ok := snapshot.find(source, destination); ok {
		return entry, nil
	}
	return linuxConnEntry{}, os.ErrNotExist
}

func linuxProcessSnapshotState(family int) (*atomic.Pointer[linuxProcessSnapshot], *sync.Mutex) {
	if family == unix.AF_INET6 {
		return &linuxIPv6ProcessSnapshotPtr, &linuxIPv6ProcessSnapshotMu
	}
	return &linuxIPv4ProcessSnapshotPtr, &linuxIPv4ProcessSnapshotMu
}

func loadLinuxProcessSnapshot(family int, ptr *atomic.Pointer[linuxProcessSnapshot], mu *sync.Mutex, force bool, seen *linuxProcessSnapshot) (*linuxProcessSnapshot, error) {
	if !force {
		if snapshot := ptr.Load(); snapshot.fresh() {
			return snapshot, nil
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if snapshot := ptr.Load(); snapshot.fresh() {
		if !force || snapshot != seen {
			return snapshot, nil
		}
	}

	entries, err := buildLinuxProcessSnapshot(family)
	if err != nil {
		return nil, err
	}
	snapshot := &linuxProcessSnapshot{createdAt: time.Now(), entries: entries}
	ptr.Store(snapshot)
	return snapshot, nil
}

func (snapshot *linuxProcessSnapshot) fresh() bool {
	const ttl = 200 * time.Millisecond
	return snapshot != nil && time.Since(snapshot.createdAt) < ttl
}

func (snapshot *linuxProcessSnapshot) find(source, destination netip.AddrPort) (linuxConnEntry, bool) {
	for _, entry := range snapshot.entries {
		if entry.match(source, destination) {
			return entry, true
		}
	}
	return linuxConnEntry{}, false
}

func (entry linuxConnEntry) match(source, destination netip.AddrPort) bool {
	return entry.src == source && entry.dst == destination
}

func buildLinuxProcessSnapshot(family int) ([]linuxConnEntry, error) {
	type inetDiagSockID struct {
		SPort  uint16
		DPort  uint16
		Src    [16]byte
		Dst    [16]byte
		If     uint32
		Cookie [2]uint32
	}
	type inetDiagReqV2 struct {
		Family   uint8
		Protocol uint8
		Ext      uint8
		Pad      uint8
		States   uint32
		ID       inetDiagSockID
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	req := inetDiagReqV2{
		Family:   uint8(family),
		Protocol: syscall.IPPROTO_TCP,
		States:   ^uint32(0),
	}
	reqdata := unsafe.Slice((*byte)(unsafe.Pointer(&req)), int(unsafe.Sizeof(req)))
	data := make([]byte, unix.SizeofNlMsghdr+len(reqdata))
	hdr := (*unix.NlMsghdr)(unsafe.Pointer(&data[0]))
	hdr.Len = uint32(len(data))
	hdr.Type = unix.SOCK_DIAG_BY_FAMILY
	hdr.Flags = unix.NLM_F_REQUEST | unix.NLM_F_DUMP
	hdr.Seq = 1
	copy(data[unix.SizeofNlMsghdr:], reqdata)

	if err = unix.Sendto(fd, data, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	var entries []linuxConnEntry
	reply := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(fd, reply, 0)
		if err != nil {
			return nil, err
		}
		for remain := reply[:n]; len(remain) >= unix.SizeofNlMsghdr; {
			h := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))
			if h.Len < unix.SizeofNlMsghdr || int(h.Len) > len(remain) {
				return nil, unix.EINVAL
			}
			payload := remain[unix.SizeofNlMsghdr:h.Len]
			switch h.Type {
			case unix.NLMSG_DONE:
				return entries, nil
			case unix.NLMSG_ERROR:
				if int(h.Len) < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
					return nil, unix.EINVAL
				}
				e := *(*unix.NlMsgerr)(unsafe.Pointer(&payload[0]))
				if e.Error == 0 {
					return entries, nil
				}
				return nil, unix.Errno(-e.Error)
			default:
				if entry, ok := parseLinuxInetDiagMsg(payload, family); ok {
					entries = append(entries, entry)
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

func parseLinuxInetDiagMsg(payload []byte, family int) (linuxConnEntry, bool) {
	type inetDiagSockID struct {
		SPort  uint16
		DPort  uint16
		Src    [16]byte
		Dst    [16]byte
		If     uint32
		Cookie [2]uint32
	}
	type inetDiagMsg struct {
		Family  uint8
		State   uint8
		Timer   uint8
		Retrans uint8
		ID      inetDiagSockID
		Expires uint32
		RQueue  uint32
		WQueue  uint32
		UID     uint32
		Inode   uint32
	}

	if len(payload) < int(unsafe.Sizeof(inetDiagMsg{})) {
		return linuxConnEntry{}, false
	}
	msg := (*inetDiagMsg)(unsafe.Pointer(&payload[0]))
	srcPort, dstPort := linuxNtohs(msg.ID.SPort), linuxNtohs(msg.ID.DPort)
	entry := linuxConnEntry{inode: uint64(msg.Inode)}
	switch family {
	case unix.AF_INET:
		var src, dst [4]byte
		copy(src[:], msg.ID.Src[:4])
		copy(dst[:], msg.ID.Dst[:4])
		entry.src = netip.AddrPortFrom(netip.AddrFrom4(src), srcPort)
		entry.dst = netip.AddrPortFrom(netip.AddrFrom4(dst), dstPort)
	case unix.AF_INET6:
		entry.src = netip.AddrPortFrom(netip.AddrFrom16(msg.ID.Src).Unmap(), srcPort)
		entry.dst = netip.AddrPortFrom(netip.AddrFrom16(msg.ID.Dst).Unmap(), dstPort)
	default:
		return linuxConnEntry{}, false
	}
	return entry, entry.src.IsValid() && entry.dst.IsValid()
}

func linuxProcessInfoFromSocketInode(inode uint64) (ConnProcessInfo, error) {
	needle := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ConnProcessInfo{}, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil {
			continue
		}
		dir := "/proc/" + entry.Name() + "/fd"
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(dir + "/" + fd.Name())
			if err != nil || target != needle {
				continue
			}
			info := ConnProcessInfo{ProcessID: pid}
			if name, err := os.ReadFile("/proc/" + entry.Name() + "/comm"); err == nil {
				info.ProcessName = strings.TrimSuffix(string(name), "\n")
			}
			return info, nil
		}
	}
	return ConnProcessInfo{}, os.ErrNotExist
}

func linuxNormalizeAddrPort(addrport netip.AddrPort) netip.AddrPort {
	if !addrport.IsValid() {
		return addrport
	}
	return netip.AddrPortFrom(addrport.Addr().Unmap(), addrport.Port())
}

func linuxNtohs(v uint16) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&v))[:])
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

func ConfigureTunInterface(name string, addressPrefix netip.Prefix, routePrefixes []netip.Prefix, metric int, bypassPrefixes []netip.Prefix) (func(), error) {
	if !addressPrefix.Addr().Is4() {
		return nil, errors.ErrUnsupported
	}
	for _, prefix := range bypassPrefixes {
		if !prefix.Addr().Is4() {
			return nil, errors.ErrUnsupported
		}
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	var addedBypass []netip.Prefix
	var addedRoutes []netip.Prefix
	cleanup := func() {
		for i := len(addedRoutes) - 1; i >= 0; i-- {
			family := "-4"
			if addedRoutes[i].Addr().Is6() {
				family = "-6"
			}
			exec.Command("ip", family, "route", "delete", addedRoutes[i].String(), "dev", name).Run()
		}
		for _, prefix := range addedBypass {
			exec.Command("ip", "-4", "route", "delete", prefix.Masked().String()).Run()
		}
	}
	ok := false
	defer func() {
		if !ok {
			cleanup()
		}
	}()

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
		return nil, fmt.Errorf("set tun address: %w", err)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("set tun link up: %w", err)
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, fmt.Errorf("set tun link up: %w", err)
	}
	if err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return nil, fmt.Errorf("set tun link up: %w", err)
	}
	if flags := ifr.Uint16(); flags&uint16(unix.IFF_UP) == 0 {
		ifr.SetUint16(flags | uint16(unix.IFF_UP))
		if err = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
			return nil, fmt.Errorf("set tun link up: %w", err)
		}
	}

	if len(bypassPrefixes) > 0 {
		run := func(args ...string) (string, error) {
			data, err := exec.Command("ip", args...).CombinedOutput()
			return strings.TrimSpace(string(data)), err
		}
		for _, prefix := range bypassPrefixes {
			msg, err := run("-4", "route", "get", prefix.Addr().String())
			if err != nil {
				return nil, fmt.Errorf("set tun bypass route: ip -4 route get %s: %w: %s", prefix.Addr(), err, msg)
			}
			var via, dev string
			fields := strings.Fields(msg)
			for i := 0; i+1 < len(fields); i++ {
				switch fields[i] {
				case "via":
					via = fields[i+1]
				case "dev":
					dev = fields[i+1]
				}
			}
			if dev == name {
				return nil, fmt.Errorf("set tun bypass route: route to %s already uses %s", prefix.Addr(), name)
			}
			if dev == "" {
				return nil, fmt.Errorf("set tun bypass route: route to %s has no device: %s", prefix.Addr(), msg)
			}
			args := []string{"-4", "route", "add", prefix.Masked().String()}
			if via != "" {
				args = append(args, "via", via)
			}
			args = append(args, "dev", dev)
			if msg, err := run(args...); err != nil {
				if strings.Contains(msg, "File exists") {
					continue
				}
				return nil, fmt.Errorf("set tun bypass route: ip %s: %w: %s", strings.Join(args, " "), err, msg)
			}
			addedBypass = append(addedBypass, prefix)
		}
	}

	if len(routePrefixes) > 0 {
		for _, route := range routePrefixes {
			route = route.Masked()
			family := uint8(unix.AF_INET)
			if route.Addr().Is6() {
				family = unix.AF_INET6
			}
			rmsg := unix.RtMsg{
				Family:   family,
				Dst_len:  uint8(route.Bits()),
				Table:    unix.RT_TABLE_MAIN,
				Protocol: unix.RTPROT_STATIC,
				Scope:    unix.RT_SCOPE_LINK,
				Type:     unix.RTN_UNICAST,
			}
			attrs := [][]byte{uint32attr(unix.RTA_OIF, uint32(iface.Index))}
			if metric > 0 {
				attrs = append(attrs, uint32attr(unix.RTA_PRIORITY, uint32(metric)))
			}
			if route.Bits() > 0 {
				if route.Addr().Is4() {
					ip4 = route.Addr().As4()
					attrs = append(attrs, attr(unix.RTA_DST, ip4[:]))
				} else {
					ip6 := route.Addr().As16()
					attrs = append(attrs, attr(unix.RTA_DST, ip6[:]))
				}
			}
			if route.Addr().Is6() {
				exec.Command("ip", "-6", "route", "delete", route.String(), "dev", name).Run()
			}
			err = update(unix.RTM_NEWROUTE, unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL, unsafe.Slice((*byte)(unsafe.Pointer(&rmsg)), unix.SizeofRtMsg), attrs...)
			if err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, fmt.Errorf("set tun route %s: %w", route, err)
			}
			if err == nil {
				addedRoutes = append(addedRoutes, route)
			}
		}
	}

	ok = true
	return cleanup, nil
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
