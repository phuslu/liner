//go:build darwin

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
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

type TCPConnProcessInfo struct {
	ID   uint64
	Name string
	Path string
}

func GetTCPConnProcessInfo(conn net.Conn) (TCPConnProcessInfo, error) {
	if conn == nil {
		return TCPConnProcessInfo{}, errors.ErrUnsupported
	}
	finder, ok := newDarwinProcessFinder(conn)
	if !ok {
		return TCPConnProcessInfo{}, errors.ErrUnsupported
	}

	entry, err := finder.find()
	if err != nil && errors.Is(err, os.ErrNotExist) {
		if fallback, ok := finder.originalDst(conn); ok {
			entry, err = fallback.find()
		}
	}
	if err != nil {
		return TCPConnProcessInfo{}, err
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

func newDarwinProcessFinder(conn net.Conn) (darwinProcessFinder, bool) {
	var finder darwinProcessFinder
	finder.source = finder.addrPort(AddrPortFromNetAddr(conn.RemoteAddr()))
	finder.destination = finder.addrPort(AddrPortFromNetAddr(conn.LocalAddr()))
	return finder, finder.source.IsValid() && finder.destination.IsValid()
}

func (finder darwinProcessFinder) originalDst(conn net.Conn) (darwinProcessFinder, bool) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return darwinProcessFinder{}, false
	}
	addrport, err := darwinGetOriginalDST(tc)
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

func (entry darwinConnEntry) processInfo() (TCPConnProcessInfo, error) {
	if entry.pid == 0 {
		return TCPConnProcessInfo{}, os.ErrNotExist
	}
	info := TCPConnProcessInfo{ID: uint64(entry.pid)}
	if path, err := entry.execPath(); err == nil && path != "" {
		info.Name = filepath.Base(path)
		info.Path = path
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
