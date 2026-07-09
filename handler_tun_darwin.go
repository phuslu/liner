//go:build darwin

package main

import (
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// tunDeviceBatchSize is the number of packets exchanged with the utun fd in
// one recvmsg_x/sendmsg_x syscall.
const tunDeviceBatchSize = 128

// tunMsghdrX mirrors struct msghdr_x from XNU bsd/sys/socket.h, consumed by
// the private recvmsg_x/sendmsg_x syscalls. The kernel fills Datalen on
// receive and ignores it on send (packet sizes come from the iovecs).
type tunMsghdrX struct {
	Msg     unix.Msghdr
	Datalen uint64
}

// tunBatchDevice wraps the wireguard darwin tun device, whose Read and Write
// move a single packet per syscall (BatchSize() == 1). utun is a
// kernel-control datagram socket, so recvmsg_x/sendmsg_x can move a whole
// batch of packets per syscall instead.
type tunBatchDevice struct {
	tun.Device
	rawConn syscall.RawConn

	readMu   sync.Mutex
	readMsgs []tunMsghdrX
	readIovs []unix.Iovec

	writeMu   sync.Mutex
	writeMsgs []tunMsghdrX
	writeIovs []unix.Iovec
}

func tunNewBatchDevice(device tun.Device) tun.Device {
	file := device.File()
	if file == nil {
		return device
	}
	rawConn, err := file.SyscallConn()
	if err != nil {
		return device
	}
	return &tunBatchDevice{
		Device:    device,
		rawConn:   rawConn,
		readMsgs:  make([]tunMsghdrX, tunDeviceBatchSize),
		readIovs:  make([]unix.Iovec, tunDeviceBatchSize),
		writeMsgs: make([]tunMsghdrX, tunDeviceBatchSize),
		writeIovs: make([]unix.Iovec, tunDeviceBatchSize),
	}
}

func (d *tunBatchDevice) BatchSize() int {
	return tunDeviceBatchSize
}

func (d *tunBatchDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < 4 {
		return d.Device.Read(bufs, sizes, offset)
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()

	count := min(len(bufs), len(sizes), tunDeviceBatchSize)
	for i := 0; i < count; i++ {
		buf := bufs[i][offset-4:]
		d.readIovs[i].Base = &buf[0]
		d.readIovs[i].Len = uint64(len(buf))
		d.readMsgs[i] = tunMsghdrX{}
		d.readMsgs[i].Msg.Iov = &d.readIovs[i]
		d.readMsgs[i].Msg.Iovlen = 1
	}

	var n int
	var errno syscall.Errno
	err := d.rawConn.Read(func(fd uintptr) bool {
		var r1 uintptr
		for {
			r1, _, errno = unix.RawSyscall6(unix.SYS_RECVMSG_X, fd, uintptr(unsafe.Pointer(&d.readMsgs[0])), uintptr(count), 0, 0, 0)
			if errno != unix.EINTR {
				break
			}
		}
		if errno == unix.EAGAIN {
			return false
		}
		n = int(r1)
		return true
	})
	switch {
	case err != nil:
		return 0, err
	case errno != 0:
		return 0, os.NewSyscallError("recvmsg_x", errno)
	}
	for i := 0; i < n; i++ {
		if size := int(d.readMsgs[i].Datalen); size >= 4 {
			sizes[i] = size - 4
		} else {
			sizes[i] = 0
		}
	}
	return n, nil
}

func (d *tunBatchDevice) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 4 {
		return d.Device.Write(bufs, offset)
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	sent := 0
	for sent < len(bufs) {
		count := min(len(bufs)-sent, tunDeviceBatchSize)
		for i := 0; i < count; i++ {
			buf := bufs[sent+i][offset-4:]
			buf[0] = 0x00
			buf[1] = 0x00
			buf[2] = 0x00
			switch buf[4] >> 4 {
			case 4:
				buf[3] = unix.AF_INET
			case 6:
				buf[3] = unix.AF_INET6
			default:
				return sent, unix.EAFNOSUPPORT
			}
			d.writeIovs[i].Base = &buf[0]
			d.writeIovs[i].Len = uint64(len(buf))
			d.writeMsgs[i] = tunMsghdrX{}
			d.writeMsgs[i].Msg.Iov = &d.writeIovs[i]
			d.writeMsgs[i].Msg.Iovlen = 1
		}

		var n int
		var errno syscall.Errno
		err := d.rawConn.Write(func(fd uintptr) bool {
			var r1 uintptr
			for {
				r1, _, errno = unix.RawSyscall6(unix.SYS_SENDMSG_X, fd, uintptr(unsafe.Pointer(&d.writeMsgs[0])), uintptr(count), 0, 0, 0)
				if errno != unix.EINTR {
					break
				}
			}
			if errno == unix.EAGAIN {
				return false
			}
			n = int(r1)
			return true
		})
		switch {
		case err != nil:
			return sent, err
		case errno == unix.ENOBUFS:
			// The utun interface queue is full and, unlike the socket-level
			// EAGAIN, draining it does not wake the write poller. Drop the
			// rest of the batch instead of stalling or killing the handler;
			// tcp recovers via retransmission.
			return len(bufs), nil
		case errno != 0:
			return sent, os.NewSyscallError("sendmsg_x", errno)
		case n <= 0:
			return sent, os.NewSyscallError("sendmsg_x", unix.EIO)
		}
		sent += n
	}
	return sent, nil
}
