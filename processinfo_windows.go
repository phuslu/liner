//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
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
	finder, ok := newWindowsProcessFinder(conn)
	if !ok {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}

	entry, err := finder.find()
	if err != nil {
		return ConnProcessInfo{}, err
	}
	return entry.processInfo()
}

func GetUDPConnProcessInfo(conn net.Conn) (ConnProcessInfo, error) {
	if conn == nil {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}
	finder, ok := newWindowsUDPProcessFinder(conn)
	if !ok {
		return ConnProcessInfo{}, errors.ErrUnsupported
	}

	entry, err := finder.find()
	if err != nil {
		return ConnProcessInfo{}, err
	}
	return entry.processInfo()
}

var (
	windowsProcGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")
	windowsProcGetExtendedUdpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedUdpTable")

	windowsIPv4ProcessSnapshotPtr atomic.Pointer[windowsProcessSnapshot]
	windowsIPv6ProcessSnapshotPtr atomic.Pointer[windowsProcessSnapshot]
	windowsIPv4ProcessSnapshotMu  sync.Mutex
	windowsIPv6ProcessSnapshotMu  sync.Mutex

	windowsIPv4UDPProcessSnapshotPtr atomic.Pointer[windowsProcessSnapshot]
	windowsIPv6UDPProcessSnapshotPtr atomic.Pointer[windowsProcessSnapshot]
	windowsIPv4UDPProcessSnapshotMu  sync.Mutex
	windowsIPv6UDPProcessSnapshotMu  sync.Mutex
)

type windowsProcessFinder struct {
	source      netip.AddrPort
	destination netip.AddrPort
	family      int
	udp         bool
	snapshot    *atomic.Pointer[windowsProcessSnapshot]
	mu          *sync.Mutex
}

type windowsConnEntry struct {
	src netip.AddrPort
	dst netip.AddrPort
	pid uint32
}

type windowsProcessSnapshot struct {
	createdAt time.Time
	entries   []windowsConnEntry
}

func newWindowsProcessFinder(conn net.Conn) (windowsProcessFinder, bool) {
	finder := windowsProcessFinder{
		family: syscall.AF_INET,
	}
	finder.source = finder.addrPort(AddrPortFromNetAddr(conn.RemoteAddr()))
	finder.destination = finder.addrPort(AddrPortFromNetAddr(conn.LocalAddr()))
	if !finder.source.IsValid() {
		return windowsProcessFinder{}, false
	}
	if finder.source.Addr().Is6() {
		finder.family = syscall.AF_INET6
		finder.snapshot = &windowsIPv6ProcessSnapshotPtr
		finder.mu = &windowsIPv6ProcessSnapshotMu
	} else {
		finder.snapshot = &windowsIPv4ProcessSnapshotPtr
		finder.mu = &windowsIPv4ProcessSnapshotMu
	}
	return finder, true
}

func newWindowsUDPProcessFinder(conn net.Conn) (windowsProcessFinder, bool) {
	finder := windowsProcessFinder{
		family: syscall.AF_INET,
		udp:    true,
	}
	finder.source = finder.addrPort(AddrPortFromNetAddr(conn.RemoteAddr()))
	if !finder.source.IsValid() {
		return windowsProcessFinder{}, false
	}
	if finder.source.Addr().Is6() {
		finder.family = syscall.AF_INET6
		finder.snapshot = &windowsIPv6UDPProcessSnapshotPtr
		finder.mu = &windowsIPv6UDPProcessSnapshotMu
	} else {
		finder.snapshot = &windowsIPv4UDPProcessSnapshotPtr
		finder.mu = &windowsIPv4UDPProcessSnapshotMu
	}
	return finder, true
}

func (finder windowsProcessFinder) addrPort(addrport netip.AddrPort) netip.AddrPort {
	if !addrport.IsValid() {
		return addrport
	}
	return netip.AddrPortFrom(addrport.Addr().Unmap(), addrport.Port())
}

func (finder windowsProcessFinder) find() (windowsConnEntry, error) {
	snapshot := finder.snapshot.Load()
	if snapshot.fresh() {
		if entry, ok := snapshot.find(finder); ok {
			return entry, nil
		}
		refreshed, err := finder.loadSnapshot(true, snapshot)
		if err != nil {
			return windowsConnEntry{}, err
		}
		if entry, ok := refreshed.find(finder); ok {
			return entry, nil
		}
		return windowsConnEntry{}, os.ErrNotExist
	}

	var err error
	snapshot, err = finder.loadSnapshot(false, snapshot)
	if err != nil {
		return windowsConnEntry{}, err
	}
	if entry, ok := snapshot.find(finder); ok {
		return entry, nil
	}
	return windowsConnEntry{}, os.ErrNotExist
}

func (finder windowsProcessFinder) loadSnapshot(force bool, seen *windowsProcessSnapshot) (*windowsProcessSnapshot, error) {
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

func (snapshot *windowsProcessSnapshot) fresh() bool {
	const ttl = 200 * time.Millisecond
	return snapshot != nil && time.Since(snapshot.createdAt) < ttl
}

func (snapshot *windowsProcessSnapshot) find(finder windowsProcessFinder) (windowsConnEntry, bool) {
	if finder.udp {
		return snapshot.findUDP(finder)
	}
	for _, entry := range snapshot.entries {
		if entry.src == finder.source {
			return entry, true
		}
	}
	return windowsConnEntry{}, false
}

func (snapshot *windowsProcessSnapshot) findUDP(finder windowsProcessFinder) (windowsConnEntry, bool) {
	for _, entry := range snapshot.entries {
		if entry.src == finder.source {
			return entry, true
		}
	}
	for _, entry := range snapshot.entries {
		addr := entry.src.Addr()
		if entry.src.Port() == finder.source.Port() && addr.IsUnspecified() && addr.BitLen() == finder.source.Addr().BitLen() {
			return entry, true
		}
	}
	return windowsConnEntry{}, false
}

func (finder windowsProcessFinder) buildSnapshot() (*windowsProcessSnapshot, error) {
	if finder.udp {
		buf, err := finder.getExtendedUdpTable()
		if err != nil {
			return nil, err
		}
		if finder.family == syscall.AF_INET6 {
			return &windowsProcessSnapshot{createdAt: time.Now(), entries: finder.parseUDP6Table(buf)}, nil
		}
		return &windowsProcessSnapshot{createdAt: time.Now(), entries: finder.parseUDPTable(buf)}, nil
	}
	buf, err := finder.getExtendedTcpTable()
	if err != nil {
		return nil, err
	}
	if finder.family == syscall.AF_INET6 {
		return &windowsProcessSnapshot{createdAt: time.Now(), entries: finder.parseTCP6Table(buf)}, nil
	}
	return &windowsProcessSnapshot{createdAt: time.Now(), entries: finder.parseTCPTable(buf)}, nil
}

func (finder windowsProcessFinder) getExtendedTcpTable() ([]byte, error) {
	const (
		tcpTableOwnerPIDConnections = 4
		initialBufferSize           = 4 * 1024
	)

	size := uint32(initialBufferSize)
	for {
		buf := make([]byte, size)
		r1, _, _ := windowsProcGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(uint32(finder.family)),
			tcpTableOwnerPIDConnections,
			0,
		)
		if r1 == windows.NO_ERROR {
			return buf, nil
		}
		errno := syscall.Errno(r1)
		if errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, os.NewSyscallError("GetExtendedTcpTable", errno)
		}
		if size == 0 {
			return nil, os.NewSyscallError("GetExtendedTcpTable", errno)
		}
	}
}

func (finder windowsProcessFinder) getExtendedUdpTable() ([]byte, error) {
	const (
		udpTableOwnerPID  = 1
		initialBufferSize = 4 * 1024
	)

	size := uint32(initialBufferSize)
	for {
		buf := make([]byte, size)
		r1, _, _ := windowsProcGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(uint32(finder.family)),
			udpTableOwnerPID,
			0,
		)
		if r1 == windows.NO_ERROR {
			return buf, nil
		}
		errno := syscall.Errno(r1)
		if errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, os.NewSyscallError("GetExtendedUdpTable", errno)
		}
		if size == 0 {
			return nil, os.NewSyscallError("GetExtendedUdpTable", errno)
		}
	}
}

func (finder windowsProcessFinder) parseTCPTable(buf []byte) []windowsConnEntry {
	type tcpRowOwnerPID struct {
		State      uint32
		LocalAddr  uint32
		LocalPort  uint32
		RemoteAddr uint32
		RemotePort uint32
		OwningPID  uint32
	}

	if len(buf) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := int(unsafe.Sizeof(tcpRowOwnerPID{}))
	offset := 4
	entries := make([]windowsConnEntry, 0, n)
	for i := 0; i < n && offset+rowSize <= len(buf); i++ {
		row := (*tcpRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		var localAddr, remoteAddr [4]byte
		binary.LittleEndian.PutUint32(localAddr[:], row.LocalAddr)
		binary.LittleEndian.PutUint32(remoteAddr[:], row.RemoteAddr)
		entries = append(entries, windowsConnEntry{
			src: netip.AddrPortFrom(netip.AddrFrom4(localAddr), windows.Ntohs(uint16(row.LocalPort))),
			dst: netip.AddrPortFrom(netip.AddrFrom4(remoteAddr), windows.Ntohs(uint16(row.RemotePort))),
			pid: row.OwningPID,
		})
		offset += rowSize
	}
	return entries
}

func (finder windowsProcessFinder) parseTCP6Table(buf []byte) []windowsConnEntry {
	type tcp6RowOwnerPID struct {
		LocalAddr     [16]byte
		LocalScopeID  uint32
		LocalPort     uint32
		RemoteAddr    [16]byte
		RemoteScopeID uint32
		RemotePort    uint32
		State         uint32
		OwningPID     uint32
	}

	if len(buf) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := int(unsafe.Sizeof(tcp6RowOwnerPID{}))
	offset := 4
	entries := make([]windowsConnEntry, 0, n)
	for i := 0; i < n && offset+rowSize <= len(buf); i++ {
		row := (*tcp6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
		entries = append(entries, windowsConnEntry{
			src: netip.AddrPortFrom(netip.AddrFrom16(row.LocalAddr), windows.Ntohs(uint16(row.LocalPort))),
			dst: netip.AddrPortFrom(netip.AddrFrom16(row.RemoteAddr), windows.Ntohs(uint16(row.RemotePort))),
			pid: row.OwningPID,
		})
		offset += rowSize
	}
	return entries
}

func (finder windowsProcessFinder) parseUDPTable(buf []byte) []windowsConnEntry {
	type udpRowOwnerPID struct {
		LocalAddr uint32
		LocalPort uint32
		OwningPID uint32
	}

	if len(buf) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := int(unsafe.Sizeof(udpRowOwnerPID{}))
	offset := 4
	entries := make([]windowsConnEntry, 0, n)
	for i := 0; i < n && offset+rowSize <= len(buf); i++ {
		row := (*udpRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		var localAddr [4]byte
		binary.LittleEndian.PutUint32(localAddr[:], row.LocalAddr)
		entries = append(entries, windowsConnEntry{
			src: netip.AddrPortFrom(netip.AddrFrom4(localAddr), windows.Ntohs(uint16(row.LocalPort))),
			pid: row.OwningPID,
		})
		offset += rowSize
	}
	return entries
}

func (finder windowsProcessFinder) parseUDP6Table(buf []byte) []windowsConnEntry {
	type udp6RowOwnerPID struct {
		LocalAddr    [16]byte
		LocalScopeID uint32
		LocalPort    uint32
		OwningPID    uint32
	}

	if len(buf) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	rowSize := int(unsafe.Sizeof(udp6RowOwnerPID{}))
	offset := 4
	entries := make([]windowsConnEntry, 0, n)
	for i := 0; i < n && offset+rowSize <= len(buf); i++ {
		row := (*udp6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
		entries = append(entries, windowsConnEntry{
			src: netip.AddrPortFrom(netip.AddrFrom16(row.LocalAddr), windows.Ntohs(uint16(row.LocalPort))),
			pid: row.OwningPID,
		})
		offset += rowSize
	}
	return entries
}

func (entry windowsConnEntry) processInfo() (ConnProcessInfo, error) {
	if entry.pid == 0 {
		return ConnProcessInfo{}, os.ErrNotExist
	}
	info := ConnProcessInfo{ID: uint64(entry.pid)}
	if path, err := entry.exePath(); err == nil && path != "" {
		info.Name = filepath.Base(path)
		info.Path = path
	}
	return info, nil
}

func (entry windowsConnEntry) exePath() (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", err
	}
	if size == 0 {
		return "", os.ErrNotExist
	}
	return windows.UTF16ToString(buf[:size]), nil
}
