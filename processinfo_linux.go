//go:build linux && !android

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ConnProcessInfo struct {
	ID   uint64
	Name string
	Path string
}

func GetTCPConnProcessInfo(conn net.Conn) (ConnProcessInfo, error) {
	if conn == nil {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}
	finder, ok := newLinuxProcessFinder(conn)
	if !ok {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}

	entry, err := finder.find()
	if err != nil && errors.Is(err, os.ErrNotExist) {
		if fallback, ok := finder.originalDst(conn); ok {
			entry, err = fallback.find()
		}
	}
	if err != nil {
		return ConnProcessInfo{}, err
	}
	if entry.inode == 0 {
		return ConnProcessInfo{}, os.ErrNotExist
	}
	return entry.processInfo()
}

func GetUDPConnProcessInfo(conn net.Conn) (ConnProcessInfo, error) {
	if conn == nil {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}
	finder, ok := newLinuxUDPProcessFinder(conn)
	if !ok {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}

	entry, err := finder.find()
	if err != nil {
		return ConnProcessInfo{}, err
	}
	if entry.inode == 0 {
		return ConnProcessInfo{}, os.ErrNotExist
	}
	return entry.processInfo()
}

var (
	linuxIPv4ProcessSnapshotPtr atomic.Pointer[linuxProcessSnapshot]
	linuxIPv6ProcessSnapshotPtr atomic.Pointer[linuxProcessSnapshot]
	linuxIPv4ProcessSnapshotMu  sync.Mutex
	linuxIPv6ProcessSnapshotMu  sync.Mutex

	linuxIPv4UDPProcessSnapshotPtr atomic.Pointer[linuxProcessSnapshot]
	linuxIPv6UDPProcessSnapshotPtr atomic.Pointer[linuxProcessSnapshot]
	linuxIPv4UDPProcessSnapshotMu  sync.Mutex
	linuxIPv6UDPProcessSnapshotMu  sync.Mutex
)

type linuxProcessFinder struct {
	source      netip.AddrPort
	destination netip.AddrPort
	family      int
	udp         bool
	snapshot    *atomic.Pointer[linuxProcessSnapshot]
	mu          *sync.Mutex
}

type linuxConnEntry struct {
	src   netip.AddrPort
	dst   netip.AddrPort
	inode uint64
}

type linuxProcessSnapshot struct {
	createdAt time.Time
	entries   []linuxConnEntry
}

func newLinuxProcessFinder(conn net.Conn) (linuxProcessFinder, bool) {
	finder := linuxProcessFinder{
		family: unix.AF_INET,
	}
	finder.source = finder.addrPort(AddrPortFromNetAddr(conn.RemoteAddr()))
	finder.destination = finder.addrPort(AddrPortFromNetAddr(conn.LocalAddr()))
	if !finder.source.IsValid() || !finder.destination.IsValid() || finder.source.Addr().BitLen() != finder.destination.Addr().BitLen() {
		return linuxProcessFinder{}, false
	}
	if finder.source.Addr().Is6() {
		finder.family = unix.AF_INET6
		finder.snapshot = &linuxIPv6ProcessSnapshotPtr
		finder.mu = &linuxIPv6ProcessSnapshotMu
	} else {
		finder.snapshot = &linuxIPv4ProcessSnapshotPtr
		finder.mu = &linuxIPv4ProcessSnapshotMu
	}
	return finder, true
}

func newLinuxUDPProcessFinder(conn net.Conn) (linuxProcessFinder, bool) {
	finder := linuxProcessFinder{
		family: unix.AF_INET,
		udp:    true,
	}
	finder.source = finder.addrPort(AddrPortFromNetAddr(conn.RemoteAddr()))
	finder.destination = finder.addrPort(AddrPortFromNetAddr(conn.LocalAddr()))
	if !finder.source.IsValid() {
		return linuxProcessFinder{}, false
	}
	if finder.destination.IsValid() && finder.source.Addr().BitLen() != finder.destination.Addr().BitLen() {
		return linuxProcessFinder{}, false
	}
	if finder.source.Addr().Is6() {
		finder.family = unix.AF_INET6
		finder.snapshot = &linuxIPv6UDPProcessSnapshotPtr
		finder.mu = &linuxIPv6UDPProcessSnapshotMu
	} else {
		finder.snapshot = &linuxIPv4UDPProcessSnapshotPtr
		finder.mu = &linuxIPv4UDPProcessSnapshotMu
	}
	return finder, true
}

func (finder linuxProcessFinder) originalDst(conn net.Conn) (linuxProcessFinder, bool) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return linuxProcessFinder{}, false
	}
	addrport, err := linuxGetOriginalDST(tc)
	if err != nil {
		return linuxProcessFinder{}, false
	}
	previous := finder.destination
	finder.destination = finder.addrPort(addrport)
	if !finder.destination.IsValid() || finder.destination == previous || finder.source.Addr().BitLen() != finder.destination.Addr().BitLen() {
		return linuxProcessFinder{}, false
	}
	return finder, true
}

func (finder linuxProcessFinder) addrPort(addrport netip.AddrPort) netip.AddrPort {
	if !addrport.IsValid() {
		return addrport
	}
	return netip.AddrPortFrom(addrport.Addr().Unmap(), addrport.Port())
}

func (finder linuxProcessFinder) find() (linuxConnEntry, error) {
	snapshot := finder.snapshot.Load()
	if snapshot.fresh() {
		if entry, ok := snapshot.find(finder); ok {
			return entry, nil
		}
		refreshed, err := finder.loadSnapshot(true, snapshot)
		if err != nil {
			return linuxConnEntry{}, err
		}
		if entry, ok := refreshed.find(finder); ok {
			return entry, nil
		}
		return linuxConnEntry{}, os.ErrNotExist
	}

	var err error
	snapshot, err = finder.loadSnapshot(false, snapshot)
	if err != nil {
		return linuxConnEntry{}, err
	}
	if entry, ok := snapshot.find(finder); ok {
		return entry, nil
	}
	return linuxConnEntry{}, os.ErrNotExist
}

func (finder linuxProcessFinder) loadSnapshot(force bool, seen *linuxProcessSnapshot) (*linuxProcessSnapshot, error) {
	if !force {
		if snapshot := finder.snapshot.Load(); snapshot.fresh() {
			return snapshot, nil
		}
	}

	finder.mu.Lock()
	defer finder.mu.Unlock()

	if snapshot := finder.snapshot.Load(); snapshot.fresh() {
		if !force || snapshot != seen {
			return snapshot, nil
		}
	}

	snapshot, err := finder.buildSnapshot()
	if err != nil {
		return nil, err
	}
	finder.snapshot.Store(snapshot)
	return snapshot, nil
}

func (snapshot *linuxProcessSnapshot) fresh() bool {
	const ttl = 200 * time.Millisecond
	return snapshot != nil && time.Since(snapshot.createdAt) < ttl
}

func (snapshot *linuxProcessSnapshot) find(finder linuxProcessFinder) (linuxConnEntry, bool) {
	if finder.udp {
		if finder.destination.IsValid() {
			for _, entry := range snapshot.entries {
				if entry.src == finder.source && entry.dst == finder.destination {
					return entry, true
				}
			}
		}
		for _, entry := range snapshot.entries {
			if entry.src == finder.source {
				return entry, true
			}
		}
		return linuxConnEntry{}, false
	}
	for _, entry := range snapshot.entries {
		if entry.src == finder.source && entry.dst == finder.destination {
			return entry, true
		}
	}
	for _, entry := range snapshot.entries {
		if entry.src == finder.source {
			return entry, true
		}
	}
	return linuxConnEntry{}, false
}

func (finder linuxProcessFinder) buildSnapshot() (*linuxProcessSnapshot, error) {
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
		Family:   uint8(finder.family),
		Protocol: syscall.IPPROTO_TCP,
		States:   ^uint32(0),
	}
	if finder.udp {
		req.Protocol = syscall.IPPROTO_UDP
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
	snapshot := &linuxProcessSnapshot{createdAt: time.Now()}
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
				snapshot.entries = entries
				return snapshot, nil
			case unix.NLMSG_ERROR:
				if int(h.Len) < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
					return nil, unix.EINVAL
				}
				e := *(*unix.NlMsgerr)(unsafe.Pointer(&payload[0]))
				if e.Error == 0 {
					snapshot.entries = entries
					return snapshot, nil
				}
				return nil, unix.Errno(-e.Error)
			default:
				if entry, ok := finder.parseInetDiagMsg(payload); ok {
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

func (finder linuxProcessFinder) parseInetDiagMsg(payload []byte) (linuxConnEntry, bool) {
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
	ntohs := func(v uint16) uint16 { return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&v))[:]) }
	srcPort, dstPort := ntohs(msg.ID.SPort), ntohs(msg.ID.DPort)
	entry := linuxConnEntry{inode: uint64(msg.Inode)}
	switch finder.family {
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

func (entry linuxConnEntry) processInfo() (ConnProcessInfo, error) {
	needle := "socket:[" + strconv.FormatUint(entry.inode, 10) + "]"
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
			info := ConnProcessInfo{ID: pid}
			if name, err := os.ReadFile("/proc/" + entry.Name() + "/comm"); err == nil {
				info.Name = strings.TrimSuffix(string(name), "\n")
			}
			if path, err := os.ReadFile("/proc/" + entry.Name() + "/exe"); err == nil {
				info.Path = strings.TrimSuffix(string(path), "\n")
			}
			return info, nil
		}
	}
	return ConnProcessInfo{}, os.ErrNotExist
}
