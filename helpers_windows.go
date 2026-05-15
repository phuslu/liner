//go:build windows

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ = fmt.Printf // for debugging log

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

func (dc DailerController) Control(network, address string, c syscall.RawConn) (err error) {
	if dc.Interface == "" {
		return nil
	}

	if ip, _ := netip.ParseAddr(dc.Interface); ip.IsValid() {
		// LocalDialer passes IP bindings through net.Dialer.LocalAddr.
		// Binding here would conflict with Go's ConnectEx setup bind.
		return nil
	}

	var controlErr error
	if err = c.Control(func(fd uintptr) {
		controlErr = dc.bindHandleToInterface(windows.Handle(fd), network, address)
	}); err != nil {
		return err
	}
	return controlErr
}

func (dc DailerController) bindHandleToInterface(handle windows.Handle, network, address string) error {
	name := strings.TrimSpace(dc.Interface)
	if name == "" {
		return errors.New("empty interface name")
	}
	size := uint32(15 * 1024)
	var ipv4Idx, ipv6Idx uint32
	for {
		buf := make([]byte, size)
		adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(syscall.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, adapter, &size)
		if err == nil {
			for aa := adapter; aa != nil; aa = aa.Next {
				friendly := windows.UTF16PtrToString(aa.FriendlyName)
				adapterName := windows.BytePtrToString(aa.AdapterName)
				if strings.EqualFold(name, friendly) || strings.EqualFold(name, adapterName) {
					ipv4Idx = aa.IfIndex
					ipv6Idx = aa.Ipv6IfIndex
					if ipv4Idx == 0 {
						ipv4Idx = ipv6Idx
					}
					if ipv6Idx == 0 {
						ipv6Idx = ipv4Idx
					}
					if ipv4Idx == 0 && ipv6Idx == 0 {
						return fmt.Errorf("interface %s has no usable index", dc.Interface)
					}
					goto indicesReady
				}
			}
			return fmt.Errorf("network interface not found: %s", dc.Interface)
		}
		if err != syscall.ERROR_BUFFER_OVERFLOW {
			return os.NewSyscallError("GetAdaptersAddresses", err)
		}
	}

indicesReady:
	family := byte(0)
	switch strings.ToLower(network) {
	case "tcp4", "udp4":
		family = 4
	case "tcp6", "udp6":
		family = 6
	default:
		host, _, err := net.SplitHostPort(address)
		if err == nil {
			if addr, perr := netip.ParseAddr(host); perr == nil {
				if addr.Is6() && !addr.Is4In6() {
					family = 6
				} else {
					family = 4
				}
			}
		}
	}

	const (
		IP_UNICAST_IF   = 31
		IPV6_UNICAST_IF = 31
	)

	setIPv4 := family != 6 && ipv4Idx != 0
	setIPv6 := family != 4 && ipv6Idx != 0
	if setIPv4 {
		if err := windows.SetsockoptInt(handle, int(syscall.IPPROTO_IP), IP_UNICAST_IF, int(bits.ReverseBytes32(ipv4Idx))); err != nil {
			switch err {
			case windows.WSAEINVAL, windows.WSAENOPROTOOPT, windows.WSAEFAULT:
				// ignored; OS doesn't support the option for this socket
			default:
				return os.NewSyscallError("setsockopt IP_UNICAST_IF", err)
			}
		}
	}
	if setIPv6 {
		if err := windows.SetsockoptInt(handle, int(windows.IPPROTO_IPV6), IPV6_UNICAST_IF, int(ipv6Idx)); err != nil {
			switch err {
			case windows.WSAEINVAL, windows.WSAENOPROTOOPT, windows.WSAEFAULT:
				// ignored; OS doesn't support the option for this socket
			default:
				return os.NewSyscallError("setsockopt IPV6_UNICAST_IF", err)
			}
		}
	}
	if !setIPv4 && !setIPv6 {
		return errors.New("no interface index available for requested family")
	}
	return nil
}

// TCPInfo mirrors the TCP_INFO_v0 structure that SIO_TCP_INFO returns on
// Windows. Only commonly used counters are exposed so templates can inspect
// basic congestion and RTT data similar to other platforms.
type TCPInfo struct {
	State             uint32  // TCPSTATE (通常是 enum -> ULONG)
	Mss               uint32  // ULONG
	ConnectionTimeMs  uint64  // ULONG64
	TimestampsEnabled uint8   // BOOLEAN (UCHAR)
	_                 [3]byte // padding 对齐到 4 字节

	RttUs         uint32 // ULONG
	MinRttUs      uint32 // ULONG
	BytesInFlight uint32 // ULONG
	Cwnd          uint32 // ULONG
	SndWnd        uint32 // ULONG
	RcvWnd        uint32 // ULONG
	RcvBuf        uint32 // ULONG

	BytesOut uint64 // ULONG64
	BytesIn  uint64 // ULONG64

	BytesReordered  uint32 // ULONG
	BytesRetrans    uint32 // ULONG
	FastRetrans     uint32 // ULONG
	DupAcksIn       uint32 // ULONG
	TimeoutEpisodes uint32 // ULONG

	SynRetrans uint8   // UCHAR
	_          [3]byte // padding (结构体对齐)
}

func (tcpinfo *TCPInfo) RTT() time.Duration {
	if tcpinfo == nil || tcpinfo.RttUs == 0 {
		return 0
	}
	return time.Duration(tcpinfo.RttUs) * time.Microsecond
}

func (ops ConnOps) GetTcpInfo() (tcpinfo *TCPInfo, err error) {
	if ops.tc == nil || ops.tc.RemoteAddr() == nil {
		return
	}

	const SIO_TCP_INFO uint32 = windows.IOC_INOUT | windows.IOC_VENDOR | 39

	var c syscall.RawConn
	c, err = ops.tc.SyscallConn()
	if err != nil {
		return
	}
	err = c.Control(func(fd uintptr) {
		var info TCPInfo
		var version uint32 = 0 // TCP_INFO_v0
		var bytesReturned uint32
		errno := windows.WSAIoctl(
			windows.Handle(fd),
			SIO_TCP_INFO,
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

func (ops ConnOps) SetTcpCongestion(name string, values ...any) (err error) {
	if ops.tc == nil {
		return errors.ErrUnsupported
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("empty congestion algorithm")
	}
	alg, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	var c syscall.RawConn
	c, err = ops.tc.SyscallConn()
	if err != nil {
		return err
	}
	err = c.Control(func(fd uintptr) {
		sz := int32(len(alg) * int(unsafe.Sizeof(alg[0])))
		if sz == 0 {
			err = errors.New("invalid congestion algorithm buffer")
			return
		}
		b := (*byte)(unsafe.Pointer(&alg[0]))
		err = windows.Setsockopt(
			windows.Handle(fd),
			int32(syscall.IPPROTO_TCP),
			int32(windows.TCP_CONGESTION_ALGORITHM),
			b,
			sz,
		)
		if err != nil {
			err = os.NewSyscallError("setsockopt IPPROTO_TCP TCP_CONGESTION_ALGORITHM "+name, err)
		}
	})
	return
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

	run := func(args ...string) (string, error) {
		data, err := exec.Command("netsh", args...).CombinedOutput()
		return strings.TrimSpace(string(data)), err
	}
	var addedBypass []netip.Prefix
	var addedRoutes []netip.Prefix
	cleanup := func() {
		for i := len(addedRoutes) - 1; i >= 0; i-- {
			route := addedRoutes[i]
			if route.Addr().Is4() {
				exec.Command("netsh", "interface", "ipv4", "delete", "route", "prefix="+route.String(), "interface="+name).Run()
			} else {
				exec.Command("netsh", "interface", "ipv6", "delete", "route", "prefix="+route.String(), "interface="+name).Run()
			}
		}
		for _, prefix := range addedBypass {
			exec.Command("netsh", "interface", "ipv4", "delete", "route", "prefix="+prefix.Masked().String()).Run()
		}
	}
	ok := false
	defer func() {
		if !ok {
			cleanup()
		}
	}()

	args := []string{"interface", "ipv4", "set", "address", "name=" + name, "source=static", "address=" + addressPrefix.Addr().String(), "mask=" + net.IP(net.CIDRMask(addressPrefix.Bits(), 32)).String(), "gateway=none", "store=active"}
	if msg, err := run(args...); err != nil {
		return nil, fmt.Errorf("set tun address: netsh %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	args = []string{"interface", "set", "interface", "name=" + name, "admin=enabled"}
	if msg, err := run(args...); err != nil {
		return nil, fmt.Errorf("set tun link up: netsh %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	if metric <= 0 {
		metric = 32767
	}
	interfaceMetric := metric
	if interfaceMetric > 9999 {
		interfaceMetric = 9999
	}
	args = []string{"interface", "ipv4", "set", "interface", "interface=" + name, fmt.Sprintf("metric=%d", interfaceMetric), "store=active"}
	if msg, err := run(args...); err != nil {
		return nil, fmt.Errorf("set tun interface metric: netsh %s: %w: %s", strings.Join(args, " "), err, msg)
	}

	if len(bypassPrefixes) > 0 {
		size := uint32(15 * 1024)
		names := make(map[uint32]string)
		metrics := make(map[uint32]uint32)
		for {
			buf := make([]byte, size)
			adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
			err := windows.GetAdaptersAddresses(syscall.AF_INET, windows.GAA_FLAG_INCLUDE_PREFIX, 0, adapter, &size)
			if err == nil {
				for aa := adapter; aa != nil; aa = aa.Next {
					if aa.IfIndex != 0 {
						names[aa.IfIndex] = windows.UTF16PtrToString(aa.FriendlyName)
						metrics[aa.IfIndex] = aa.Ipv4Metric
					}
				}
				break
			}
			if err != syscall.ERROR_BUFFER_OVERFLOW {
				return nil, os.NewSyscallError("GetAdaptersAddresses", err)
			}
		}

		var table *windows.MibIpForwardTable2
		if err := windows.GetIpForwardTable2(syscall.AF_INET, &table); err != nil {
			return nil, os.NewSyscallError("GetIpForwardTable2", err)
		}
		defer windows.FreeMibTable(unsafe.Pointer(table))

		addrFromSockaddr := func(sa windows.RawSockaddrInet, allowUnspecified bool) (netip.Addr, bool) {
			if sa.Family == 0 && allowUnspecified {
				return netip.AddrFrom4([4]byte{}), true
			}
			if sa.Family != syscall.AF_INET {
				return netip.Addr{}, false
			}
			raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(&sa))
			return netip.AddrFrom4(raw.Addr), true
		}
		routeTo := func(prefix netip.Prefix) (iface, gateway string, ok bool) {
			bestBits := -1
			bestMetric := ^uint64(0)
			for _, row := range table.Rows() {
				if row.DestinationPrefix.PrefixLength > 32 || strings.EqualFold(names[row.InterfaceIndex], name) {
					continue
				}
				dst, ok := addrFromSockaddr(row.DestinationPrefix.Prefix, false)
				if !ok {
					continue
				}
				route := netip.PrefixFrom(dst, int(row.DestinationPrefix.PrefixLength)).Masked()
				if !route.Contains(prefix.Addr()) {
					continue
				}
				next, ok := addrFromSockaddr(row.NextHop, true)
				if !ok {
					continue
				}
				bits := int(row.DestinationPrefix.PrefixLength)
				metric := uint64(row.Metric) + uint64(metrics[row.InterfaceIndex])
				if bits < bestBits || bits == bestBits && metric >= bestMetric {
					continue
				}
				iface = cmp.Or(names[row.InterfaceIndex], fmt.Sprint(row.InterfaceIndex))
				gateway = next.String()
				bestBits = bits
				bestMetric = metric
			}
			return iface, gateway, iface != ""
		}
		for _, prefix := range bypassPrefixes {
			iface, gateway, ok := routeTo(prefix)
			if !ok {
				continue
			}
			args = []string{"interface", "ipv4", "add", "route", "prefix=" + prefix.Masked().String(), "interface=" + iface, "metric=1", "store=active"}
			if gateway != "" && gateway != "0.0.0.0" {
				args = append(args, "nexthop="+gateway)
			}
			if msg, err := run(args...); err != nil {
				if strings.Contains(strings.ToLower(msg), "exist") {
					continue
				}
				return nil, fmt.Errorf("set tun bypass route: netsh %s: %w: %s", strings.Join(args, " "), err, msg)
			}
			addedBypass = append(addedBypass, prefix)
		}
	}

	for _, route := range routePrefixes {
		route = route.Masked()
		family := "ipv4"
		if route.Addr().Is6() {
			family = "ipv6"
		}
		exec.Command("netsh", "interface", family, "delete", "route", "prefix="+route.String(), "interface="+name).Run()
		args = []string{"interface", family, "add", "route", "prefix=" + route.String(), "interface=" + name, fmt.Sprintf("metric=%d", metric), "store=active"}
		if msg, err := run(args...); err != nil {
			if strings.Contains(strings.ToLower(msg), "exist") {
				args = []string{"interface", family, "set", "route", "prefix=" + route.String(), "interface=" + name, fmt.Sprintf("metric=%d", metric), "store=active"}
				if msg, err = run(args...); err != nil {
					return nil, fmt.Errorf("set tun route: netsh %s: %w: %s", strings.Join(args, " "), err, msg)
				}
			} else {
				return nil, fmt.Errorf("set tun route: netsh %s: %w: %s", strings.Join(args, " "), err, msg)
			}
		}
		addedRoutes = append(addedRoutes, route)
	}

	ok = true
	return cleanup, nil
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
