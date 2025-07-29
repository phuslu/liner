// Modified from github.com/hnakamur/go-sshd

package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/phuslu/log"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

type SshHandler struct {
	Config SshConfig
	Logger log.Logger

	sshConfig   *ssh.ServerConfig
	userchecker AuthUserChecker
	keyloader   *FileLoader[[]string]
	shellPath   string
	closed      atomic.Bool
}

func (h *SshHandler) Load() error {
	if len(h.Config.Listen) != 1 {
		return fmt.Errorf("invalid ssh listen: %v", h.Config.Listen)
	}

	var sshSigner ssh.Signer
	if h.Config.HostKey != "" {
		key, err := os.ReadFile(h.Config.HostKey)
		if err != nil {
			return fmt.Errorf("Failed to load private key (%s): %w", h.Config.HostKey, err)
		}
		sshSigner, err = ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("Failed to parse private key; %w", err)
		}
	} else {
		log.Warn().Strs("ssh_listens", h.Config.Listen).Msg("host_key is not configured, generating ssh key.")
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("Failed to generate ed25519 key; %w", err)
		}
		sshSigner, err = ssh.NewSignerFromKey(key)
		if err != nil {
			return fmt.Errorf("Failed to create ssh private key; %w", err)
		}
	}

	h.sshConfig = &ssh.ServerConfig{
		ServerVersion: cmp.Or(h.Config.ServerVersion, fmt.Sprintf("SSH-2.0-liner-%s", version)),
		MaxAuthTries:  3,
	}
	h.sshConfig.AddHostKey(sshSigner)

	if h.Config.AuthTable != "" {
		if table := os.ExpandEnv(h.Config.AuthTable); table != "" {
			loader := NewAuthUserLoaderFromTable(table)
			records, err := loader.LoadAuthUsers(context.Background())
			if err != nil {
				log.Fatal().Err(err).Strs("ssh_listens", h.Config.Listen).Str("auth_table", table).Msg("load auth_table failed")
			}
			log.Info().Strs("ssh_listens", h.Config.Listen).Str("auth_table", table).Int("auth_table_size", len(records)).Msg("load auth_table ok")
			h.userchecker = &AuthUserLoadChecker{loader}
		}

		h.sshConfig.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			user := AuthUserInfo{
				Username: c.User(),
				Password: string(pass),
			}
			err := h.userchecker.CheckAuthUser(context.Background(), &user)
			if allow := user.Attrs["allow_ssh"]; allow != "" {
				switch allow {
				case "0":
					err = fmt.Errorf("wrong permission, allow_ssh is %s: %v", allow, user.Username)
				}
			}
			if err != nil {
				return nil, err
			}
			return nil, nil
		}
	}

	if h.Config.AuthorizedKeys != "" {
		h.Config.AuthorizedKeys = os.ExpandEnv(h.Config.AuthorizedKeys)
		h.keyloader = &FileLoader[[]string]{
			Filename: h.Config.AuthorizedKeys,
			Unmarshal: func(data []byte, v any) error {
				keys, ok := v.(*[]string)
				if !ok {
					return fmt.Errorf("*[]string required, found %T", v)
				}

				for len(data) > 0 {
					pub, _, _, rest, err := ssh.ParseAuthorizedKey(data)
					if err != nil {
						h.Logger.Printf("parse authorized_keys %#v error: %+v", h.Config.AuthorizedKeys, err)
					}
					if pub != nil {
						*keys = AppendSplitLines(*keys, string(pub.Marshal()))
					}
					data = rest
				}
				slices.Sort(*keys)
				return nil
			},
			PollDuration: 30 * time.Second,
			Logger:       log.DefaultLogger.Slog(),
		}
		h.sshConfig.PublicKeyCallback = func(c ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
			records := *h.keyloader.Load()
			if len(records) == 0 {
				return nil, fmt.Errorf("empty authorized_keys in ssh host")
			}
			_, ok := slices.BinarySearchFunc(records, b2s(pub.Marshal()), func(a, b string) int { return cmp.Compare(a, b) })
			if !ok {
				return nil, fmt.Errorf("invalid pub key: %s", pub.Marshal())
			}
			return &ssh.Permissions{
				// Record the public key used for authentication.
				Extensions: map[string]string{
					"pubkey-fp": ssh.FingerprintSHA256(pub),
				},
			}, nil
		}
	}

	h.shellPath = h.Config.Shell
	if h.shellPath == "" {
		h.shellPath = "/bin/sh"
	}
	if h.shellPath[0] != '/' {
		if _, err := exec.LookPath(h.shellPath); err != nil {
			return fmt.Errorf("invalid shell path: %w", err)
		}
	}

	return nil
}

// ListenAndServe let the server listen and serve.
func (s *SshHandler) Serve(ctx context.Context, ln net.Listener) error {
	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			return fmt.Errorf("accept incoming connection: %s", err)
		}
		if c, ok := tcpConn.(*net.TCPConn); ok {
			c.SetReadBuffer(cmp.Or(s.Config.TcpReadBuffer, 65536))
			if !s.Config.DisableKeepalive {
				c.SetKeepAliveConfig(net.KeepAliveConfig{
					Enable:   true,
					Idle:     15 * time.Second,
					Interval: 15 * time.Second,
					Count:    9,
				})
			}
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		go s.handleConn(ctx, tcpConn)
	}
}

func (s *SshHandler) handleConn(ctx context.Context, tcpConn net.Conn) {
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
	go s.handleChannels(ctx, chans)
}

func (s *SshHandler) handleChannels(ctx context.Context, chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go s.handleChannel(ctx, newChannel)
	}
}

func (s *SshHandler) handleChannel(ctx context.Context, newChannel ssh.NewChannel) {
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
		envs := map[string]string{}

		for req := range requests {
			//fmt.Printf("req=%+v\n", req)
			switch req.Type {
			case "exec":
				req.Reply(true, nil)

				length := int(binary.BigEndian.Uint32(req.Payload))
				command := string(req.Payload[4:])
				if len(command) != length {
					log.Fatal().Msgf("command length unmatch, got=%d, want=%d", len(command), length)
				}

				shellcmd := exec.CommandContext(ctx, s.shellPath, "-c", command)

				var err error
				var in io.WriteCloser
				var out io.ReadCloser

				// Prepare teardown function
				close := func() {
					in.Close()

					err := shellcmd.Wait()
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

				in, err = shellcmd.StdinPipe()
				if err != nil {
					s.Logger.Printf("Could not get stdin pipe (%s)", err)
					close()
					return
				}

				out, err = shellcmd.StdoutPipe()
				if err != nil {
					s.Logger.Printf("Could not get stdout pipe (%s)", err)
					close()
					return
				}

				err = shellcmd.Start()
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
			case "env":
				if len(req.Payload) == 0 {
					if len(req.Payload) < 8 {
						s.Logger.Warn().Msg("Invalid env request payload")
						req.Reply(false, nil)
						continue
					}
					keylen := binary.BigEndian.Uint32(req.Payload[0:4])
					if len(req.Payload) < 4+int(keylen)+4 {
						s.Logger.Warn().Msg("Invalid env request payload")
						req.Reply(false, nil)
						continue
					}
					key := string(req.Payload[4 : 4+keylen])
					valuelen := binary.BigEndian.Uint32(req.Payload[4+keylen:])
					value := string(req.Payload[4+keylen+4 : 4+keylen+4+valuelen])
					envs[key] = value
					s.Logger.Info().Str("req_type", req.Type).Str("key", key).Str("value", value).Msg("handle ssh request")
				}
				req.Reply(true, nil)
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)

					var err error
					// Fire up bash for this session
					shellfile, err = s.startShell(ctx, s.shellPath, envs, connection)
					if err != nil {
						s.Logger.Error().Err(err).Str("req_type", req.Type).Str("shell", s.shellPath).Any("envs", envs).Msg("handle ssh request")
						req.Reply(false, nil)
					}

					// Set window size
					if width > 0 && height > 0 {
						SetTermWindowSize(shellfile.Fd(), uint16(width), uint16(height))
					}
				}
			case "pty-req":
				length := req.Payload[3]
				width = binary.BigEndian.Uint32(req.Payload[length+4:])
				height = binary.BigEndian.Uint32(req.Payload[length+8:])
				s.Logger.Info().Str("req_type", req.Type).Uint32("width", width).Uint32("height", height).Msg("handle ssh request")
				if shellfile != nil {
					SetTermWindowSize(shellfile.Fd(), uint16(width), uint16(height))
				}
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				width = binary.BigEndian.Uint32(req.Payload[0:])
				height = binary.BigEndian.Uint32(req.Payload[4:])
				s.Logger.Info().Str("req_type", req.Type).Uint32("width", width).Uint32("height", height).Msg("handle ssh request")
				if shellfile != nil {
					SetTermWindowSize(shellfile.Fd(), uint16(width), uint16(height))
				}
			case "subsystem":
				switch {
				case strings.HasSuffix(b2s(req.Payload), "sftp"):
					s.Logger.Printf("sftp server serving: %s", req.Payload)
					go func() {
						defer connection.Close()
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
					req.Reply(true, nil)
				default:
					s.Logger.Printf("ssh subsystem request %#v not supportted", req)
					req.Reply(false, append([]byte("ssh subsystem is not supportted: "), req.Payload...))
				}
			case "keepalive@openssh.com":
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()
}

func (s *SshHandler) startShell(ctx context.Context, shellPath string, envs map[string]string, connection ssh.Channel) (*os.File, error) {
	shell := exec.CommandContext(ctx, shellPath)
	shell.Dir = os.ExpandEnv(cmp.Or(s.Config.Home, "$HOME"))
	shell.Env = []string{
		"SHELL=" + shellPath,
		"HOME=" + cmp.Or(s.Config.Home, os.Getenv("HOME"), "/"),
		"TERM=" + "linux",
	}
	for key, value := range envs {
		shell.Env = append(shell.Env, key+"="+value)
	}

	// Prepare teardown function
	close := func() {
		if shell.Process != nil {
			shell.Process.Signal(os.Interrupt)
			timer := time.AfterFunc(time.Minute, func() { shell.Process.Signal(os.Kill) })
			defer timer.Stop()
		}
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
		return nil, err
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

	return file, nil
}
