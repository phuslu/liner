//go:build linux

package main

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/phuslu/gosh"
	"github.com/phuslu/pamtester"
	"golang.org/x/term"
)

func login() int {
	var preserveEnv bool
	var rhost, loginName string
	usage := func() {
		fmt.Fprintln(os.Stderr, "usage: login [-p] [-h host] [-login-name name] [username]")
		fmt.Fprintln(os.Stderr, "  -h host")
		fmt.Fprintln(os.Stderr, "    \tremote host for PAM_RHOST")
		fmt.Fprintln(os.Stderr, "  -login-name name")
		fmt.Fprintln(os.Stderr, "    \tnon-root login name (defaults to LOGIN_NAME)")
		fmt.Fprintln(os.Stderr, "  -p")
		fmt.Fprintln(os.Stderr, "    \tdo not clear the environment")
	}

	username := ""
	usernameSet := false
	parseOptions := true
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if parseOptions && arg == "--" {
			parseOptions = false
			continue
		}
		if !parseOptions || arg == "" || arg[0] != '-' || arg == "-" {
			if usernameSet {
				usage()
				fmt.Fprintln(os.Stderr, "login: too many arguments")
				return 2
			}
			username = arg
			usernameSet = true
			continue
		}

		name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
		value := ""
		hasValue := false
		if before, after, ok := strings.Cut(name, "="); ok {
			name, value, hasValue = before, after, true
		}
		switch name {
		case "p":
			preserveEnv = true
			if hasValue {
				var err error
				preserveEnv, err = strconv.ParseBool(value)
				if err != nil {
					fmt.Fprintf(os.Stderr, "login: invalid value %q for -p: %v\n", value, err)
					return 2
				}
			}
		case "h", "login-name":
			if !hasValue {
				if i+1 >= len(args) {
					fmt.Fprintf(os.Stderr, "login: option %s requires a value\n", arg)
					return 2
				}
				i++
				value = args[i]
			}
			if name == "h" {
				rhost = value
			} else {
				loginName = value
			}
		case "help":
			usage()
			return 0
		default:
			usage()
			fmt.Fprintf(os.Stderr, "login: unknown option %s\n", arg)
			return 2
		}
	}

	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "login:", err)
		return 1
	}

	realUID := os.Getuid()
	current, err := user.LookupId(strconv.Itoa(realUID))
	if err != nil {
		return fail(fmt.Errorf("look up current user: %w", err))
	}
	if realUID != 0 && loginName == "" {
		loginName = os.Getenv("LOGIN_NAME")
	}

	tty := ""
	for _, fd := range []uintptr{os.Stdin.Fd(), os.Stderr.Fd()} {
		if path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil && strings.HasPrefix(path, "/dev/") {
			tty = strings.TrimPrefix(path, "/dev/")
			break
		}
	}

	reader := bufio.NewReader(os.Stdin)
	readLine := func() (string, error) {
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	readPassword := func() ([]byte, error) {
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			fmt.Fprint(os.Stderr, "Password: ")
			line, err := readLine()
			fmt.Fprintln(os.Stderr)
			return []byte(line), err
		}
		fmt.Fprint(os.Stderr, "Password: ")
		password, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return password, err
	}
	printMessages := func(messages []string) {
		for _, message := range messages {
			fmt.Fprintln(os.Stderr, message)
		}
	}
	authenticate := func(username string, password []byte) (string, error) {
		tx, err := pamtester.Start(username, &pamtester.Options{
			Service: "login",
			RHost:   rhost,
			TTY:     tty,
			RUser:   current.Username,
		})
		if err != nil {
			return "", fmt.Errorf("start PAM transaction: %w", err)
		}
		defer tx.Close()

		if err := tx.Authenticate(string(password)); err != nil {
			return "", err
		}
		printMessages(tx.Messages())
		if err := tx.AcctMgmt(); err != nil {
			return "", err
		}
		printMessages(tx.Messages())
		pamUser, err := tx.User()
		if err != nil {
			return "", fmt.Errorf("read PAM user: %w", err)
		}
		if pamUser == "" {
			return "", errors.New("PAM returned an empty user")
		}
		if err := tx.Close(); err != nil {
			return "", fmt.Errorf("close PAM transaction: %w", err)
		}
		return pamUser, nil
	}
	loginRejected := func(err error) bool {
		return errors.Is(err, pamtester.ErrAuth) ||
			errors.Is(err, pamtester.ErrUserUnknown) ||
			errors.Is(err, pamtester.ErrMaxTries) ||
			errors.Is(err, pamtester.ErrAcctExpired) ||
			errors.Is(err, pamtester.ErrPermDenied) ||
			errors.Is(err, pamtester.ErrNewAuthTokReqd)
	}

	for {
		targetName := username
		username = "" // A supplied username applies to the first attempt only.
		if targetName == "" {
			fmt.Fprint(os.Stderr, "login: ")
			targetName, err = readLine()
			if errors.Is(err, io.EOF) {
				return 0
			}
			if err != nil {
				return fail(fmt.Errorf("read username: %w", err))
			}
			if targetName == "" {
				targetName = current.Username
			}
		}

		var target *user.User
		loginNameMatches := true
		if realUID != 0 {
			expectedName := cmp.Or(loginName, current.Username)
			// Authenticate before rejecting a mismatched name so response
			// timing cannot be used to enumerate login names.
			loginNameMatches = targetName == expectedName
			target = current
		} else {
			target, err = user.Lookup(targetName)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Login incorrect")
				continue
			}
		}

		password, err := readPassword()
		if err != nil {
			clear(password)
			return fail(fmt.Errorf("read password: %w", err))
		}
		pamUser, err := authenticate(target.Username, password)
		clear(password)
		if err != nil {
			if loginRejected(err) {
				fmt.Fprintln(os.Stderr, "Login incorrect")
				continue
			}
			return fail(err)
		}

		pamTarget, err := user.Lookup(pamUser)
		if err != nil {
			return fail(fmt.Errorf("look up PAM user %q: %w", pamUser, err))
		}
		if realUID != 0 {
			if pamTarget.Uid != current.Uid || !loginNameMatches {
				fmt.Fprintln(os.Stderr, "Login incorrect")
				continue
			}
			// LOGIN_NAME is display-only. Credentials and the shell always
			// come from the invoking user's real account.
			target = current
		} else {
			target = pamTarget
		}
		if err := startLoginShell(target, preserveEnv); err != nil {
			return fail(err)
		}
		return 0
	}
}

func startLoginShell(target *user.User, preserveEnv bool) error {
	uid, err := strconv.Atoi(target.Uid)
	if err != nil {
		return fmt.Errorf("invalid uid %q: %w", target.Uid, err)
	}
	gid, err := strconv.Atoi(target.Gid)
	if err != nil {
		return fmt.Errorf("invalid gid %q: %w", target.Gid, err)
	}
	if os.Getuid() != 0 && os.Getuid() != uid {
		return errors.New("refusing to switch to another user")
	}

	shell := func() string {
		file, err := os.Open("/etc/passwd")
		if err != nil {
			return "/bin/sh"
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) >= 7 && fields[0] == target.Username &&
				filepath.IsAbs(fields[6]) && !strings.ContainsRune(fields[6], 0) {
				return fields[6]
			}
		}
		// NSS users need not have a local passwd entry. /bin/sh will still
		// source the account profile through argv[0].
		return "/bin/sh"
	}()

	if os.Geteuid() == 0 {
		ids, err := target.GroupIds()
		if err != nil {
			return fmt.Errorf("look up groups for %s: %w", target.Username, err)
		}
		groups := make([]int, 0, len(ids)+1)
		seen := map[int]bool{gid: true}
		groups = append(groups, gid)
		for _, idText := range ids {
			id, err := strconv.Atoi(idText)
			if err != nil {
				return fmt.Errorf("invalid supplementary gid %q: %w", idText, err)
			}
			if !seen[id] {
				seen[id] = true
				groups = append(groups, id)
			}
		}
		if err := syscall.Setgroups(groups); err != nil {
			return fmt.Errorf("set supplementary groups: %w", err)
		}
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("set gid: %w", err)
		}
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("set uid: %w", err)
		}
	}
	if os.Getuid() != uid || os.Geteuid() != uid {
		return fmt.Errorf("credential switch failed: uid=%d euid=%d, want %d", os.Getuid(), os.Geteuid(), uid)
	}

	if err := os.Chdir(target.HomeDir); err != nil {
		return fmt.Errorf("change directory to %s: %w", target.HomeDir, err)
	}
	syscall.Umask(0o022)

	var env []string
	if preserveEnv {
		env = append(env, os.Environ()...)
	} else if name := os.Getenv("TERM"); name != "" {
		env = append(env, "TERM="+name)
	}
	for key, value := range map[string]string{
		"HOME":    target.HomeDir,
		"LOGNAME": target.Username,
		"MAIL":    filepath.Join("/var/mail", target.Username),
		"PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"SHELL":   shell,
		"USER":    target.Username,
	} {
		env = gosh.SetEnv(env, key, value)
	}

	argv0 := "-" + filepath.Base(shell)
	if err := syscall.Exec(shell, []string{argv0}, env); err != nil {
		return fmt.Errorf("exec %s: %w", shell, err)
	}
	return nil
}
