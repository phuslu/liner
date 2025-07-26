package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
	"github.com/zeebo/wyhash"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

type AuthUserInfo struct {
	Username string            `json:"username"`
	Password string            `json:"password"`
	Attrs    map[string]string `json:"attrs"`
}

type AuthUserChecker interface {
	CheckAuthUser(context.Context, *AuthUserInfo) error
}

type AuthUserLoader interface {
	LoadAuthUsers(context.Context) ([]AuthUserInfo, error)
}

type AuthUserLoadChecker struct {
	AuthUserLoader
}

func (c *AuthUserLoadChecker) CheckAuthUser(ctx context.Context, user *AuthUserInfo) (err error) {
	records, err := c.AuthUserLoader.LoadAuthUsers(ctx)
	if err != nil {
		return fmt.Errorf("userloader %T error: %w", c.AuthUserLoader, err)
	}

	i, ok := slices.BinarySearchFunc(records, *user, func(a, b AuthUserInfo) int { return cmp.Compare(a.Username, b.Username) })
	switch {
	case !ok:
		err = fmt.Errorf("invalid username: %v", user.Username)
	case user.Password == records[i].Password:
		*user = records[i]
	case strings.HasPrefix(records[i].Password, "0x"):
		var b []byte
		b, err = hex.AppendDecode(make([]byte, 0, 64), s2b(records[i].Password[2:]))
		if err != nil {
			err = fmt.Errorf("invalid sha1/sha256 password: %v", records[i].Password)
			return
		}
		switch len(b) {
		case 8:
			if binary.BigEndian.Uint64(b) == wyhash.HashString(user.Password, 0) {
				*user = records[i]
				return
			}
		case 20:
			if *(*[20]byte)(b) == sha1.Sum(s2b(user.Password)) {
				*user = records[i]
				return
			}
		case 32:
			if *(*[32]byte)(b) == sha256.Sum256(s2b(user.Password)) {
				*user = records[i]
				return
			}
		}
		err = fmt.Errorf("invalid md5/sha1/sha256 password: %v", records[i].Password)
		return
	case strings.HasPrefix(records[i].Password, "$2y$"):
		err = bcrypt.CompareHashAndPassword([]byte(records[i].Password), []byte(user.Password))
		if err == nil {
			*user = records[i]
		} else {
			err = fmt.Errorf("wrong password: %v: %w", user.Username, err)
		}
	case strings.HasPrefix(records[i].Password, "$argon2id$"):
		// see https://github.com/alexedwards/argon2id
		// $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
		argon2idRegex := sync.OnceValue(func() *regexp.Regexp {
			return regexp.MustCompile(`^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$(.+)\$(.+)$`)
		})()
		ms := argon2idRegex.FindStringSubmatch(records[i].Password)
		if ms == nil {
			err = fmt.Errorf("invalid argon2id password: %v", records[i].Password)
			return
		}
		m, t, p := first(strconv.Atoi(ms[2])), first(strconv.Atoi(ms[3])), first(strconv.Atoi(ms[4]))
		var salt, key []byte
		salt, err = base64.RawStdEncoding.Strict().DecodeString(ms[5])
		if err != nil {
			err = fmt.Errorf("invalid argon2id password: %v : %w", records[i].Password, err)
			return
		}
		key, err = base64.RawStdEncoding.Strict().DecodeString(ms[6])
		if err != nil {
			err = fmt.Errorf("invalid argon2id password: %v : %w", records[i].Password, err)
			return
		}
		idkey := argon2.IDKey([]byte(user.Password), salt, uint32(t), uint32(m), uint8(p), uint32(len(key)))
		if subtle.ConstantTimeEq(int32(len(key)), int32(len(idkey))) == 0 ||
			subtle.ConstantTimeCompare(key, idkey) != 1 {
			err = fmt.Errorf("wrong password: %v", user.Username)
		}
	default:
		err = fmt.Errorf("wrong password: %v", user.Username)
	}

	return
}

var _ AuthUserLoader = (*AuthUserFileLoader)(nil)

type AuthUserFileLoader struct {
	Filename  string
	Unmarshal func(data []byte, v any) error
	Logger    *slog.Logger

	fileloader *FileLoader[[]AuthUserInfo]
}

var authfileloaders = xsync.NewMap[string, *FileLoader[[]AuthUserInfo]](xsync.WithSerialResize())

func (loader *AuthUserFileLoader) LoadAuthUsers(ctx context.Context) ([]AuthUserInfo, error) {
	if loader.fileloader == nil {
		loader.fileloader = sync.OnceValue(func() *FileLoader[[]AuthUserInfo] {
			fileloader, _ := authfileloaders.LoadOrCompute(loader.Filename, func() (*FileLoader[[]AuthUserInfo], bool) {
				return &FileLoader[[]AuthUserInfo]{
					Filename:     loader.Filename,
					Unmarshal:    loader.Unmarshal,
					Logger:       cmp.Or(loader.Logger, slog.Default()),
					PollDuration: 15 * time.Second,
				}, false
			})
			return fileloader
		})()
	}

	return *loader.fileloader.Load(), nil
}

/*

username,password,speed_limit,allow_tunnel,allow_client,allow_ssh,allow_webdav
foo,123456,-1,1,0,0,0
bar,qwerty,0,0,1,0,0

*/

func AuthUserFileCSVUnmarshaler(data []byte, v any) error {
	infos, ok := v.(*[]AuthUserInfo)
	if !ok {
		return fmt.Errorf("*[]AuthUserInfo required, found %T", v)
	}

	records, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		return err
	}
	if len(records) <= 1 {
		return fmt.Errorf("no csv rows in %q", data)
	}

	names := records[0]
	for _, parts := range records[1:] {
		if len(parts) <= 1 {
			continue
		}
		var user AuthUserInfo
		for i, part := range parts {
			switch i {
			case 0:
				user.Username = part
			case 1:
				user.Password = part
			default:
				if user.Attrs == nil {
					user.Attrs = make(map[string]string)
				}
				if i >= len(names) {
					return fmt.Errorf("overflow csv cloumn, names=%v parts=%v", names, parts)
				}
				user.Attrs[names[i]] = part
			}
		}
		*infos = append(*infos, user)
	}

	slices.SortFunc(*infos, func(a, b AuthUserInfo) int { return cmp.Compare(a.Username, b.Username) })

	return nil
}

/*

{"username":"foo","password":"123456","attrs":{"speed_limit":"-1","allow_tunnel":"0","allow_client":"0"}}
{"username":"bar","qwerty":"123456","attrs":{"speed_limit":"0","allow_tunnel":"0","allow_client":"1"}}

*/

func AuthUserFileJSONUnmarshaler(data []byte, v any) error {
	infos, ok := v.(*[]AuthUserInfo)
	if !ok {
		return fmt.Errorf("*[]AuthUserInfo required, found %T", v)
	}

	for line := range bytes.Lines(data) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var info AuthUserInfo
		err := json.Unmarshal(line, &info)
		if err != nil {
			return err
		}
		*infos = append(*infos, info)
	}

	slices.SortFunc(*infos, func(a, b AuthUserInfo) int { return cmp.Compare(a.Username, b.Username) })

	return nil
}

var _ AuthUserLoader = (*AuthUserCommandLoader)(nil)

type AuthUserCommandLoader struct {
	Command  string
	Logger   *slog.Logger
	CacheTTL time.Duration

	users atomic.Value // []AuthUserInfo
	mtime atomic.Int64 // timestamp
}

func (loader *AuthUserCommandLoader) LoadAuthUsers(ctx context.Context) ([]AuthUserInfo, error) {
	if loader.CacheTTL > 0 {
		if ts := loader.mtime.Load(); 0 < ts && ts+int64(loader.CacheTTL) < time.Now().UnixNano() {
			return loader.users.Load().([]AuthUserInfo), nil
		}
	}

	if len(loader.Command) == 0 {
		return nil, fmt.Errorf("AuthUserCommandLoader: command is not configured")
	}

	cmd := exec.CommandContext(ctx, loader.Command)
	cmd.Env = []string{}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("load auth users failed: %w: %s", err, string(output))
	}

	users := make([]AuthUserInfo, strings.Count(b2s(output), "\n")+1)
	if bytes.HasPrefix(output, []byte{'{'}) {
		err = AuthUserFileJSONUnmarshaler(output, &users)
	} else {
		err = AuthUserFileCSVUnmarshaler(output, &users)
	}
	if err != nil {
		return nil, err
	}

	loader.users.Store(users)
	loader.mtime.Store(time.Now().UnixNano())

	return users, nil
}

var _ AuthUserChecker = (*AuthUserCommandChecker)(nil)

type AuthUserCommandChecker struct {
	Command string
	Logger  *slog.Logger
}

func (loader *AuthUserCommandChecker) CheckAuthUser(ctx context.Context, user *AuthUserInfo) error {
	if len(loader.Command) == 0 {
		return fmt.Errorf("AuthUserCommandChecker: command is not configured")
	}

	cmd := exec.CommandContext(ctx, loader.Command)
	cmd.Env = []string{
		"USERNAME=" + user.Username,
		"PASSWORD=" + user.Password,
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("authentication failed for user %q: %w: %s", user.Username, err, output)
	}

	if err := json.Unmarshal(output, user); err != nil {
		return fmt.Errorf("failed to parse user attributes from command output for user %q: %w: %s", user.Username, err, string(output))
	}

	return nil
}

// NewAuthUserLoaderFromTable is a helper function for handlers
func NewAuthUserLoaderFromTable(table string) AuthUserLoader {
	var loader AuthUserLoader
	switch {
	case strings.HasSuffix(table, ".csv") && !strings.Contains(table, " "):
		loader = &AuthUserFileLoader{Filename: table, Unmarshal: AuthUserFileCSVUnmarshaler}
	case strings.HasSuffix(table, ".json") && !strings.Contains(table, " "):
		loader = &AuthUserFileLoader{Filename: table, Unmarshal: AuthUserFileJSONUnmarshaler}
	default:
		loader = &AuthUserCommandLoader{Command: table}
	}
	return loader
}
