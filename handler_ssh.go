//go:build !windows
// +build !windows

// Modified from github.com/hnakamur/go-sshd

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/phuslu/log"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type SSHHandler struct {
	shellPath string
	config    *ssh.ServerConfig
	logger    *log.Logger
	listener  net.Listener

	mu     sync.Mutex
	closed bool
}

// ListenAndServe let the server listen and serve.
func (s *SSHHandler) ListenAndServe(addr string) error {
	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %s", addr, err)
	}
	return s.Serve(listener)
}

// Serve let the server accept incoming connections and handle them.
func (s *SSHHandler) Serve(l net.Listener) error {
	s.listener = l
	for {
		tcpConn, err := l.Accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return fmt.Errorf("accept incoming connection: %s", err)
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		go s.handleConn(tcpConn)
	}
}

func (s *SSHHandler) handleConn(tcpConn net.Conn) {
	// Before use, a handshake must be performed on the incoming net.Conn.
	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.config)
	if err != nil {
		if err != io.EOF {
			log.Printf("Failed to handshake (%s)", err)
		}
		return
	}
	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
	// Discard all global out-of-band Requests
	go ssh.DiscardRequests(reqs)
	// Accept all channels
	go s.handleChannels(chans)
}

// Close stops the server.
func (s *SSHHandler) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Close()
}

func (s *SSHHandler) isClosed() bool {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return closed
}

func (s *SSHHandler) handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go s.handleChannel(newChannel)
	}
}

func (s *SSHHandler) handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		s.logger.Printf("Could not accept channel (%s)", err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		var shellf *SSHShellFile

		for req := range requests {
			//fmt.Printf("req=%+v\n", req)
			switch req.Type {
			case "exec":
				req.Reply(true, nil)

				cmd := parseCommand(req.Payload)
				shell := exec.Command(s.shellPath, "-c", cmd)

				var err error
				var in io.WriteCloser
				var out io.ReadCloser

				// Prepare teardown function
				close := func() {
					in.Close()

					err := shell.Wait()
					var exitStatus int32
					if err != nil {
						if e2, ok := err.(*exec.ExitError); ok {
							if s, ok := e2.Sys().(syscall.WaitStatus); ok {
								exitStatus = int32(s.ExitStatus())
							} else {
								panic(errors.New("unimplemented for system where exec.ExitError.Sys() is not syscall.WaitStatus"))
							}
						}
					}
					var b bytes.Buffer
					binary.Write(&b, binary.BigEndian, exitStatus)
					connection.SendRequest("exit-status", false, b.Bytes())
					connection.Close()
					s.logger.Printf("Session closed")
				}

				in, err = shell.StdinPipe()
				if err != nil {
					s.logger.Printf("Could not get stdin pipe (%s)", err)
					close()
					return
				}

				out, err = shell.StdoutPipe()
				if err != nil {
					s.logger.Printf("Could not get stdout pipe (%s)", err)
					close()
					return
				}

				err = shell.Start()
				if err != nil {
					s.logger.Printf("Could not start pty (%s)", err)
					close()
					return
				}

				//pipe session to shell and visa-versa
				var once sync.Once
				go func() {
					io.Copy(connection, out)
					once.Do(close)
				}()
				go func() {
					io.Copy(in, connection)
					once.Do(close)
				}()
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)

					// Fire up bash for this session
					shellf = s.startShell(s.shellPath, connection)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				shellf.setWinsize(w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				shellf.setWinsize(w, h)
			case "subsystem":
				ok := string(req.Payload[4:]) == "sftp"
				if ok {
					go func() {
						server, err := sftp.NewServer(connection)
						if err != nil {
							s.logger.Printf("could not start sftp server: %s", err)
							return
						}
						if err := server.Serve(); err == io.EOF {
							server.Close()
							s.logger.Printf("sftp client exited session.")
						} else if err != nil {
							s.logger.Printf("sftp server exited with error: %s", err)
						}
					}()
				}
				req.Reply(ok, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()
}

func parseCommand(b []byte) string {
	l := int(binary.BigEndian.Uint32(b))
	cmd := string(b[4:])
	if len(cmd) != l {
		log.Fatalf("command length unmatch, got=%d, want=%d", len(cmd), l)
	}
	return cmd
}

func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

type SSHShellFile struct {
	file *os.File
}

// start shell
func (s *SSHHandler) startShell(shellPath string, connection ssh.Channel) *SSHShellFile {
	shell := exec.Command(shellPath)

	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := shell.Process.Wait()
		if err != nil {
			s.logger.Printf("Failed to exit shell (%s)", err)
		}
		s.logger.Printf("Session closed")
	}

	// Allocate a terminal for this channel
	s.logger.Print("Creating pty...")
	file, err := pty.Start(shell)
	if err != nil {
		s.logger.Printf("Could not start pty (%s)", err)
		close()
		return nil
	}

	//pipe session to shell and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, file)
		once.Do(close)
	}()
	go func() {
		io.Copy(file, connection)
		once.Do(close)
	}()
	return &SSHShellFile{file}
}

// SetWinsize sets the size of the given pty.
func (sf *SSHShellFile) setWinsize(w, h uint32) {
	ws := &struct {
		Height uint16
		Width  uint16
		x      uint16 // unused
		y      uint16 // unused
	}{
		Width:  uint16(w),
		Height: uint16(h),
	}

	syscall.Syscall(syscall.SYS_IOCTL, sf.file.Fd(), uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
