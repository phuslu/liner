//go:build darwin

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
	FastOpen    bool
	ReusePort   bool // macOS not supported
	DeferAccept bool // macOS not supported
}

func (lc ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	const TCP_FASTOPEN = 0x105 // macOS: /usr/include/netinet/tcp.h

	ln := &net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				if lc.FastOpen {
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
				}
				// ReusePort: macos not supported，skip
				// DeferAccept: macos not supported，skip
			})
		},
	}

	return ln.Listen(ctx, network, address)
}

func (lc ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

type DailerController struct {
	Interface string
}

func (dc DailerController) Control(network, addr string, c syscall.RawConn) (err error) {
	if dc.Interface == "" {
		return nil
	}

	text := strings.TrimSpace(dc.Interface)
	if ip, parseErr := netip.ParseAddr(text); parseErr == nil && ip.IsValid() {
		// LocalDialer passes IP bindings through net.Dialer.LocalAddr.
		return nil
	}

	ifi, err := net.InterfaceByName(text)
	if err != nil {
		if idx, convErr := strconv.Atoi(text); convErr == nil && idx > 0 {
			ifi, err = net.InterfaceByIndex(idx)
		}
	}
	if err != nil {
		return fmt.Errorf("network interface not found: %s", text)
	}
	if ifi.Index <= 0 {
		return fmt.Errorf("invalid interface index for %s", text)
	}

	var controlErr error
	if err = c.Control(func(fd uintptr) {
		family := 0
		host := addr
		if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
			host = h
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsValid() {
			if ip.Is6() && !ip.Is4In6() {
				family = 6
			} else {
				family = 4
			}
		} else {
			switch strings.ToLower(network) {
			case "tcp4", "udp4", "ip4":
				family = 4
			case "tcp6", "udp6", "ip6":
				family = 6
			}
		}

		switch family {
		case 4:
			if soErr := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, ifi.Index); soErr != nil {
				controlErr = os.NewSyscallError("setsockopt IP_BOUND_IF", soErr)
			}
		case 6:
			if soErr := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, ifi.Index); soErr != nil {
				controlErr = os.NewSyscallError("setsockopt IPV6_BOUND_IF", soErr)
			}
		default:
			if soErr := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, ifi.Index); soErr == nil {
				controlErr = nil
				return
			} else {
				ignore := false
				if errno, ok := soErr.(syscall.Errno); ok {
					switch errno {
					case syscall.EAFNOSUPPORT, syscall.EPROTONOSUPPORT, syscall.ENOPROTOOPT, syscall.EOPNOTSUPP, syscall.ENOTSUP:
						ignore = true
					}
				}
				if !ignore {
					controlErr = os.NewSyscallError("setsockopt IP_BOUND_IF", soErr)
					return
				}
			}
			if soErr := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, ifi.Index); soErr == nil {
				controlErr = nil
				return
			} else {
				ignore := false
				if errno, ok := soErr.(syscall.Errno); ok {
					switch errno {
					case syscall.EAFNOSUPPORT, syscall.EPROTONOSUPPORT, syscall.ENOPROTOOPT, syscall.EOPNOTSUPP, syscall.ENOTSUP:
						ignore = true
					}
				}
				if !ignore {
					controlErr = os.NewSyscallError("setsockopt IPV6_BOUND_IF", soErr)
					return
				}
				controlErr = errors.New("failed to bind socket to interface")
			}
		}
	}); err != nil {
		return err
	}
	return controlErr
}

type TCPInfo unix.TCPConnectionInfo

func (tcpinfo *TCPInfo) RTT() time.Duration {
	if tcpinfo == nil {
		return 0
	}
	if tcpinfo.Srtt > 0 {
		return time.Duration(tcpinfo.Srtt) * time.Millisecond
	}
	if tcpinfo.Rttcur > 0 {
		return time.Duration(tcpinfo.Rttcur) * time.Millisecond
	}
	return 0
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
		var info *unix.TCPConnectionInfo
		info, err = unix.GetsockoptTCPConnectionInfo(int(fd), syscall.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
		if err != nil {
			return
		}
		v := TCPInfo(*info)
		tcpinfo = &v
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
	finder, ok := newDarwinProcessFinder(ops.tc)
	if !ok {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}

	entry, err := finder.find()
	if err != nil && errors.Is(err, os.ErrNotExist) {
		if fallback, ok := finder.originalDst(ops); ok {
			entry, err = fallback.find()
		}
	}
	if err != nil {
		return ConnProcessInfo{}, err
	}
	return entry.processInfo()
}

type darwinProcessFinder struct {
	source      netip.AddrPort
	destination netip.AddrPort
}

var darwinPCBStructSize = func() int {
	value, _ := syscall.Sysctl("kern.osrelease")
	major, _, _ := strings.Cut(value, ".")
	n, _ := strconv.ParseInt(major, 10, 64)
	if n >= 22 {
		return 408
	}
	// From XNU in_pcblist_n: round-up aligned sizes of xinpcb_n, xsocket_n,
	// two xsockbuf_n values, and xsockstat_n.
	return 384
}()

type darwinConnEntry struct {
	src netip.AddrPort
	dst netip.AddrPort
	pid uint32
}

type darwinProcessSnapshot struct {
	createdAt time.Time
	entries   []darwinConnEntry
}

var (
	darwinProcessSnapshotPtr atomic.Pointer[darwinProcessSnapshot]
	darwinProcessSnapshotMu  sync.Mutex
)

func newDarwinProcessFinder(conn *net.TCPConn) (darwinProcessFinder, bool) {
	var finder darwinProcessFinder
	finder.source = finder.addrPort(AddrPortFromNetAddr(conn.RemoteAddr()))
	finder.destination = finder.addrPort(AddrPortFromNetAddr(conn.LocalAddr()))
	return finder, finder.source.IsValid() && finder.destination.IsValid()
}

func (finder darwinProcessFinder) originalDst(ops ConnOps) (darwinProcessFinder, bool) {
	addrport, err := ops.GetOriginalDST()
	if err != nil {
		return darwinProcessFinder{}, false
	}
	previous := finder.destination
	finder.destination = finder.addrPort(addrport)
	return finder, finder.destination.IsValid() && finder.destination != previous
}

func (finder darwinProcessFinder) addrPort(addrport netip.AddrPort) netip.AddrPort {
	if !addrport.IsValid() {
		return addrport
	}
	return netip.AddrPortFrom(addrport.Addr().Unmap(), addrport.Port())
}

func (finder darwinProcessFinder) find() (darwinConnEntry, error) {
	snapshot := darwinProcessSnapshotPtr.Load()
	if snapshot.fresh() {
		if entry, ok := snapshot.find(finder); ok {
			return entry, nil
		}
		refreshed, err := finder.loadSnapshot(true, snapshot)
		if err != nil {
			return darwinConnEntry{}, err
		}
		if entry, ok := refreshed.find(finder); ok {
			return entry, nil
		}
		return darwinConnEntry{}, os.ErrNotExist
	}

	var err error
	snapshot, err = finder.loadSnapshot(false, snapshot)
	if err != nil {
		return darwinConnEntry{}, err
	}
	if entry, ok := snapshot.find(finder); ok {
		return entry, nil
	}
	return darwinConnEntry{}, os.ErrNotExist
}

func (finder darwinProcessFinder) loadSnapshot(force bool, seen *darwinProcessSnapshot) (*darwinProcessSnapshot, error) {
	if !force {
		if snapshot := darwinProcessSnapshotPtr.Load(); snapshot.fresh() {
			return snapshot, nil
		}
	}

	darwinProcessSnapshotMu.Lock()
	defer darwinProcessSnapshotMu.Unlock()

	if snapshot := darwinProcessSnapshotPtr.Load(); snapshot.fresh() {
		if !force || snapshot != seen {
			return snapshot, nil
		}
	}

	snapshot, err := finder.buildSnapshot()
	if err != nil {
		return nil, err
	}
	darwinProcessSnapshotPtr.Store(snapshot)
	return snapshot, nil
}

func (snapshot *darwinProcessSnapshot) fresh() bool {
	const ttl = 200 * time.Millisecond
	return snapshot != nil && time.Since(snapshot.createdAt) < ttl
}

func (snapshot *darwinProcessSnapshot) find(finder darwinProcessFinder) (darwinConnEntry, bool) {
	for _, entry := range snapshot.entries {
		if entry.src == finder.source && entry.dst == finder.destination {
			return entry, true
		}
	}
	return darwinConnEntry{}, false
}

func (entry darwinConnEntry) processInfo() (ConnProcessInfo, error) {
	if entry.pid == 0 {
		return ConnProcessInfo{}, os.ErrNotExist
	}
	info := ConnProcessInfo{ProcessID: uint64(entry.pid)}
	if path, err := entry.execPath(); err == nil && path != "" {
		info.ProcessName = filepath.Base(path)
	}
	return info, nil
}

func (finder darwinProcessFinder) buildSnapshot() (*darwinProcessSnapshot, error) {
	const tcpExtraStructSize = 208

	value, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
	if err != nil {
		return nil, fmt.Errorf("tcp pcblist: %w", err)
	}
	return &darwinProcessSnapshot{createdAt: time.Now(), entries: finder.parseSnapshot(value, darwinPCBStructSize+tcpExtraStructSize)}, nil
}

func (finder darwinProcessFinder) parseSnapshot(buf []byte, itemSize int) []darwinConnEntry {
	const xinpgenSize = 24

	if itemSize <= 0 || len(buf) <= xinpgenSize {
		return nil
	}
	entries := make([]darwinConnEntry, 0, (len(buf)-xinpgenSize)/itemSize)
	for i := xinpgenSize; i+itemSize <= len(buf); i += itemSize {
		if entry, ok := finder.parseEntry(buf[i : i+itemSize]); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func (finder darwinProcessFinder) parseEntry(buf []byte) (darwinConnEntry, bool) {
	const (
		xsocketOffset       = 104
		foreignPort         = 16
		localPort           = 18
		vflag               = 44
		foreignAddr         = 48
		localAddr           = 64
		ipv4Addr            = 12
		xsocketLastPID      = 68
		vflagIPV4      byte = 0x1
		vflagIPV6      byte = 0x2
	)

	if len(buf) < darwinPCBStructSize {
		return darwinConnEntry{}, false
	}
	srcPort := binary.BigEndian.Uint16(buf[localPort : localPort+2])
	dstPort := binary.BigEndian.Uint16(buf[foreignPort : foreignPort+2])
	entry := darwinConnEntry{pid: binary.NativeEndian.Uint32(buf[xsocketOffset+xsocketLastPID : xsocketOffset+xsocketLastPID+4])}
	switch flag := buf[vflag]; {
	case flag&vflagIPV4 != 0:
		var remote, local [4]byte
		copy(remote[:], buf[foreignAddr+ipv4Addr:foreignAddr+ipv4Addr+4])
		copy(local[:], buf[localAddr+ipv4Addr:localAddr+ipv4Addr+4])
		entry.src = netip.AddrPortFrom(netip.AddrFrom4(local), srcPort)
		entry.dst = netip.AddrPortFrom(netip.AddrFrom4(remote), dstPort)
	case flag&vflagIPV6 != 0:
		var remote, local [16]byte
		copy(remote[:], buf[foreignAddr:foreignAddr+16])
		copy(local[:], buf[localAddr:localAddr+16])
		entry.src = netip.AddrPortFrom(netip.AddrFrom16(local), srcPort)
		entry.dst = netip.AddrPortFrom(netip.AddrFrom16(remote), dstPort)
	default:
		return darwinConnEntry{}, false
	}
	return entry, true
}

func (entry darwinConnEntry) execPath() (string, error) {
	const (
		procPIDPathInfo     = 0xb
		procPIDPathInfoSize = 1024
		procCallNumPIDInfo  = 0x2
	)
	var buf [procPIDPathInfoSize]byte
	n, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		procCallNumPIDInfo,
		uintptr(entry.pid),
		procPIDPathInfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return "", errno
	}
	if n == 0 {
		return "", os.ErrNotExist
	}
	return unix.ByteSliceToString(buf[:]), nil
}

func (ops ConnOps) GetOriginalDST() (addrport netip.AddrPort, err error) {
	if ops.tc == nil {
		return
	}

	// Keep these local PF ioctl definitions in sync with Apple XNU:
	// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h
	// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ioctl.c
	const (
		PF_OUT      = 2
		DIOCNATLOOK = 0xc0544417 // _IOWR('D', 23, struct pfioc_natlook)
	)

	type PFINatLook struct {
		SAddr        [16]byte
		DAddr        [16]byte
		RSAddr       [16]byte
		RDAddr       [16]byte
		SXPort       [4]byte
		DXPort       [4]byte
		RSXPort      [4]byte
		RDXPort      [4]byte
		AF           byte
		Proto        byte
		ProtoVariant byte
		Direction    byte
	}

	raddr := AddrPortFromNetAddr(ops.tc.RemoteAddr())
	laddr := AddrPortFromNetAddr(ops.tc.LocalAddr())
	if !raddr.IsValid() || !laddr.IsValid() {
		err = errors.ErrUnsupported
		return
	}

	var nl PFINatLook
	rip, lip := raddr.Addr(), laddr.Addr()
	switch {
	case rip.Is4() && lip.Is4():
		rip4 := rip.As4()
		lip4 := lip.As4()
		copy(nl.SAddr[:4], rip4[:])
		copy(nl.DAddr[:4], lip4[:])
		nl.AF = unix.AF_INET
	case rip.Is6() && lip.Is6():
		rip6 := rip.As16()
		lip6 := lip.As16()
		copy(nl.SAddr[:], rip6[:])
		copy(nl.DAddr[:], lip6[:])
		nl.AF = unix.AF_INET6
	default:
		err = fmt.Errorf("pf nat lookup: %w", errors.ErrUnsupported)
		return
	}
	binary.BigEndian.PutUint16(nl.SXPort[:2], raddr.Port())
	binary.BigEndian.PutUint16(nl.DXPort[:2], laddr.Port())
	nl.Proto = unix.IPPROTO_TCP
	nl.Direction = PF_OUT

	file, lookupErr := os.OpenFile("/dev/pf", os.O_RDONLY, 0)
	if lookupErr != nil {
		err = fmt.Errorf("pf nat lookup: %w", lookupErr)
		return
	}
	defer file.Close()

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), DIOCNATLOOK, uintptr(unsafe.Pointer(&nl)))
	if errno != 0 {
		err = fmt.Errorf("pf nat lookup: %w", errno)
		return
	}

	var addr netip.Addr
	switch nl.AF {
	case unix.AF_INET:
		var v [4]byte
		copy(v[:], nl.RDAddr[:4])
		addr = netip.AddrFrom4(v)
	case unix.AF_INET6:
		addr = netip.AddrFrom16(nl.RDAddr)
	default:
		err = fmt.Errorf("pf nat lookup: %w", errors.ErrUnsupported)
		return
	}
	port := binary.BigEndian.Uint16(nl.RDXPort[:2])
	if !addr.IsValid() || port == 0 {
		err = fmt.Errorf("pf nat lookup: %w", errors.ErrUnsupported)
		return
	}
	addrport = netip.AddrPortFrom(addr, port)
	return
}

func (ops ConnOps) SetTcpCongestion(name string, values ...any) (err error) {
	return errors.ErrUnsupported
}

func (ops ConnOps) SetTcpMaxPacingRate(rate int) error {
	return errors.ErrUnsupported
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

	run := func(command string, args ...string) (string, error) {
		data, err := exec.Command(command, args...).CombinedOutput()
		return strings.TrimSpace(string(data)), err
	}
	routeProbeAddr := func(prefix netip.Prefix) netip.Addr {
		addr := prefix.Addr()
		if prefix.Bits() < addr.BitLen() {
			if next := addr.Next(); next.IsValid() && prefix.Contains(next) {
				addr = next
			}
		}
		return addr
	}
	type tunRoute struct {
		prefix netip.Prefix
		scoped bool
	}
	var addedBypass []netip.Prefix
	var addedRoutes []tunRoute
	cleanup := func() {
		for i := len(addedRoutes) - 1; i >= 0; i-- {
			route := addedRoutes[i]
			dst := route.prefix.Masked().String()
			args := []string{"-n", "delete"}
			if route.prefix.Addr().Is6() {
				args = append(args, "-inet6")
			}
			args = append(args, "-net")
			if route.scoped {
				args = append(args, "-ifscope", name)
			}
			exec.Command("route", append(args, dst, "-interface", name)...).Run()
		}
		for _, prefix := range addedBypass {
			args := []string{"-n", "delete", "-host", prefix.Addr().String()}
			if prefix.Bits() != 32 {
				args = []string{"-n", "delete", "-net", prefix.Masked().String()}
			}
			exec.Command("route", args...).Run()
		}
	}
	ok := false
	defer func() {
		if !ok {
			cleanup()
		}
	}()

	mask := net.IP(net.CIDRMask(addressPrefix.Bits(), 32)).String()
	ip := addressPrefix.Addr().String()
	args := []string{name, "inet", ip, ip, "netmask", mask, "up"}
	if msg, err := run("ifconfig", args...); err != nil {
		return nil, fmt.Errorf("set tun address: ifconfig %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	args = []string{name, "up"}
	if msg, err := run("ifconfig", args...); err != nil {
		return nil, fmt.Errorf("set tun link up: ifconfig %s: %w: %s", strings.Join(args, " "), err, msg)
	}

	for _, prefix := range bypassPrefixes {
		if prefix.Addr().IsLoopback() {
			continue
		}
		probeAddr := routeProbeAddr(prefix)
		msg, err := run("route", "-n", "get", probeAddr.String())
		if err != nil {
			return nil, fmt.Errorf("set tun bypass route: route -n get %s: %w: %s", probeAddr, err, msg)
		}
		var gateway, iface string
		for line := range strings.Lines(msg) {
			key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok {
				continue
			}
			switch strings.TrimSpace(key) {
			case "gateway":
				gateway = strings.TrimSpace(value)
			case "interface":
				iface = strings.TrimSpace(value)
			case "ifscope":
				if iface == "" {
					iface = strings.TrimSpace(value)
				}
			}
		}
		if iface == name {
			return nil, fmt.Errorf("set tun bypass route: route to %s already uses %s", probeAddr, name)
		}
		args = []string{"-n", "add", "-host", prefix.Addr().String()}
		if prefix.Bits() != 32 {
			args = []string{"-n", "add", "-net", prefix.Masked().String()}
		}
		if gateway != "" && !strings.HasPrefix(gateway, "link#") {
			args = append(args, gateway)
		} else if iface != "" {
			args = append(args, "-interface", iface)
		} else if indexText, ok := strings.CutPrefix(gateway, "link#"); ok {
			index, err := strconv.Atoi(indexText)
			if err != nil {
				return nil, fmt.Errorf("set tun bypass route: route to %s has invalid link gateway %s: %w", probeAddr, gateway, err)
			}
			ifi, err := net.InterfaceByIndex(index)
			if err != nil {
				return nil, fmt.Errorf("set tun bypass route: route to %s has invalid link gateway %s: %w", probeAddr, gateway, err)
			}
			args = append(args, "-interface", ifi.Name)
		} else {
			return nil, fmt.Errorf("set tun bypass route: route to %s has no gateway or interface: %s", probeAddr, msg)
		}
		if msg, err := run("route", args...); err != nil {
			if strings.Contains(msg, "File exists") {
				continue
			}
			return nil, fmt.Errorf("set tun bypass route: route %s: %w: %s", strings.Join(args, " "), err, msg)
		}
		addedBypass = append(addedBypass, prefix)
	}

	scopes := []bool{false, true}
	routes := make([]netip.Prefix, 0, len(routePrefixes))
	for _, route := range routePrefixes {
		routes = append(routes, route.Masked())
	}
	for _, route := range routes {
		for _, scoped := range scopes {
			args = []string{"-n", "add"}
			if route.Addr().Is6() {
				args = append(args, "-inet6")
			}
			args = append(args, "-net")
			if scoped {
				args = append(args, "-ifscope", name)
			}
			args = append(args, route.String(), "-interface", name)
			if route.Addr().Is6() {
				delargs := append([]string(nil), args...)
				delargs[1] = "delete"
				exec.Command("route", delargs...).Run()
			}
			if msg, err := run("route", args...); err != nil {
				if strings.Contains(msg, "File exists") {
					continue
				}
				return nil, fmt.Errorf("set tun route: route %s: %w: %s", strings.Join(args, " "), err, msg)
			}
			addedRoutes = append(addedRoutes, tunRoute{route, scoped})
		}
	}

	ok = true
	return cleanup, nil
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

	written := copy(argv0, name+strings.Repeat("\x00", n+1-len(name)))
	if written < len(argv0) {
		argv0[written] = 0
	}

	return nil
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
	if err := syscall.Dup2(int(file.Fd()), 1); err != nil {
		return err
	}
	if err := syscall.Dup2(int(file.Fd()), 2); err != nil {
		return err
	}
	return nil
}

func AppendSetSidToSysProcAttr(old *syscall.SysProcAttr, uid, gid int) *syscall.SysProcAttr {
	return old
}

func EnableVirtualTerminalSequences() error {
	return nil
}
