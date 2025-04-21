// Modified from github.com/hnakamur/go-sshd

package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/phuslu/log"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type SshHandler struct {
	Config SshConfig
	Logger log.Logger

	sshConfig *ssh.ServerConfig
	csvloader *FileLoader[[]UserInfo]
	shellPath string

	mu     sync.Mutex
	closed bool
}

func (h *SshHandler) Load() error {
	if len(h.Config.Listen) != 1 {
		return fmt.Errorf("invalid ssh listen: %v", h.Config.Listen)
	}
	if h.Config.HostKey == "" {
		return fmt.Errorf("invalid ssh host_key: %v", h.Config.HostKey)
	}

	h.sshConfig = &ssh.ServerConfig{
		//Define a function to run when a client attempts a password login
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
		// You may also explicitly allow anonymous client authentication, though anon bash
		// sessions may not be a wise idea
		// NoClientAuth: true,
	}

	privdata, err := os.ReadFile(h.Config.HostKey)
	if err != nil {
		return fmt.Errorf("Failed to load private key (%s): %w", h.Config.HostKey, err)
	}

	privkey, err := ssh.ParsePrivateKey(privdata)
	if err != nil {
		return fmt.Errorf("Failed to parse private key; %w", err)
	}

	h.sshConfig.AddHostKey(privkey)

	if strings.HasSuffix(h.Config.AuthTable, ".csv") {
		h.csvloader = &FileLoader[[]UserInfo]{
			Filename:     h.Config.AuthTable,
			Unmarshal:    UserCsvUnmarshal,
			PollDuration: 15 * time.Second,
			Logger:       log.DefaultLogger.Slog(),
		}
		records := h.csvloader.Load()
		if records == nil {
			return fmt.Errorf("Failed to load auth_table: %#v", h.Config.AuthTable)
		}
		log.Info().Str("auth_table", h.Config.AuthTable).Int("auth_table_size", len(*records)).Msg("load auth_table ok")

		h.sshConfig.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			user := UserInfo{
				Username: c.User(),
				Password: string(pass),
			}
			records := *h.csvloader.Load()
			i, ok := slices.BinarySearchFunc(records, user, func(a, b UserInfo) int { return cmp.Compare(a.Username, b.Username) })
			switch {
			case !ok:
				user.AuthError = fmt.Errorf("invalid username: %v", user.Username)
			case user.Password != records[i].Password:
				user.AuthError = fmt.Errorf("wrong password: %v", user.Username)
			default:
				user = records[i]
			}
			if user.AuthError != nil {
				return nil, user.AuthError
			}
			return nil, nil
		}
	}

	h.shellPath = h.Config.Shell
	if h.shellPath == "" {
		h.shellPath = "/bin/sh"
	}

	return nil
}

// ListenAndServe let the server listen and serve.
func (s *SshHandler) Serve(ctx context.Context, ln net.Listener) error {
	for {
		tcpConn, err := ln.Accept()
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

func (s *SshHandler) handleConn(tcpConn net.Conn) {
	// Before use, a handshake must be performed on the incoming net.Conn.
	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.sshConfig)
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

func (s *SshHandler) isClosed() bool {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return closed
}

func (s *SshHandler) handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go s.handleChannel(newChannel)
	}
}

func (s *SshHandler) handleChannel(newChannel ssh.NewChannel) {
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
		s.Logger.Printf("Could not accept channel (%s)", err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		var shellfile *os.File
		var width, height uint32

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
					s.Logger.Printf("Session closed")
				}

				in, err = shell.StdinPipe()
				if err != nil {
					s.Logger.Printf("Could not get stdin pipe (%s)", err)
					close()
					return
				}

				out, err = shell.StdoutPipe()
				if err != nil {
					s.Logger.Printf("Could not get stdout pipe (%s)", err)
					close()
					return
				}

				err = shell.Start()
				if err != nil {
					s.Logger.Printf("Could not start pty (%s)", err)
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
					shellfile = s.startShell(s.shellPath, connection)

					// Set window size
					if width > 0 && height > 0 {
						SetTermWindowSize(shellfile.Fd(), uint16(width), uint16(height))
					}
				}
			case "pty-req":
				termLen := req.Payload[3]
				width, height = parseDims(req.Payload[termLen+4:])
				if shellfile != nil {
					SetTermWindowSize(shellfile.Fd(), uint16(width), uint16(height))
				}
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				width, height = parseDims(req.Payload)
				if shellfile != nil {
					SetTermWindowSize(shellfile.Fd(), uint16(width), uint16(height))
				}
			case "subsystem":
				ok := string(req.Payload[4:]) == "sftp"
				if ok {
					go func() {
						server, err := sftp.NewServer(connection)
						if err != nil {
							s.Logger.Printf("could not start sftp server: %s", err)
							return
						}
						if err := server.Serve(); err == io.EOF {
							server.Close()
							s.Logger.Printf("sftp client exited session.")
						} else if err != nil {
							s.Logger.Printf("sftp server exited with error: %s", err)
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
		log.Fatal().Msgf("command length unmatch, got=%d, want=%d", len(cmd), l)
	}
	return cmd
}

func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

func (s *SshHandler) startShell(shellPath string, connection ssh.Channel) *os.File {
	shell := exec.Command(shellPath)

	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := shell.Process.Wait()
		if err != nil {
			s.Logger.Printf("Failed to exit shell (%s)", err)
		}
		s.Logger.Printf("Session closed")
	}

	// Allocate a terminal for this channel
	s.Logger.Printf("Creating pty...")
	file, err := pty.Start(shell)
	if err != nil {
		s.Logger.Printf("Could not start pty (%s)", err)
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

	return file
}
