//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

func (ops ConnOps) GetOriginalDST() (addrport netip.AddrPort, err error) {
	// macOS has no netfilter, so SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST are unavailable.
	// When using pf(4) for transparent proxying, the original destination can be retrieved
	// via getsockname, provided pf is configured with rdr-to or divert-to rules.
	if ops.tc == nil {
		return
	}
	// macOS transparent proxying typically relies on pf + DIOCNATLOOK ioctl to query the NAT table.
	// This is a best-effort fallback using getsockname, valid only under rdr-to scenarios.
	addrport = AddrPortFromNetAddr(ops.tc.LocalAddr())
	if !addrport.IsValid() {
		err = errors.ErrUnsupported
	}
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
