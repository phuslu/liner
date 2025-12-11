package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
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
	LoadAuthUsers(context.Context) (map[string]AuthUserInfo, error)
}

var _ AuthUserChecker = (*AuthUserLoadChecker)(nil)

type AuthUserLoadChecker struct {
	AuthUserLoader
}

// see https://github.com/alexedwards/argon2id
// $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
var argon2idRegex = regexp.MustCompile(`^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$(.+)\$(.+)$`)

func (c *AuthUserLoadChecker) CheckAuthUser(ctx context.Context, user *AuthUserInfo) (err error) {
	records, err := c.AuthUserLoader.LoadAuthUsers(ctx)
	if err != nil {
		return fmt.Errorf("userloader %T error: %w", c.AuthUserLoader, err)
	}

	record, ok := records[user.Username]
	switch {
	case !ok:
		err = fmt.Errorf("invalid username: %v", user.Username)
	case user.Password == record.Password:
		*user = record
	case strings.HasPrefix(record.Password, "0x"):
		var b []byte
		b, err = hex.AppendDecode(make([]byte, 0, 64), s2b(record.Password[2:]))
		if err != nil {
			err = fmt.Errorf("invalid sha1/sha256 password: %v", record.Password)
			return
		}
		switch len(b) {
		case md5.Size:
			if *(*[md5.Size]byte)(b) == md5.Sum(s2b(user.Password)) {
				*user = record
				return
			}
		case sha1.Size:
			if *(*[sha1.Size]byte)(b) == sha1.Sum(s2b(user.Password)) {
				*user = record
				return
			}
		case sha256.Size:
			if *(*[sha256.Size]byte)(b) == sha256.Sum256(s2b(user.Password)) {
				*user = record
				return
			}
		}
		err = fmt.Errorf("invalid md5/sha1/sha256 password: %v", record.Password)
		return
	case strings.HasPrefix(record.Password, "$2y$"):
		err = bcrypt.CompareHashAndPassword([]byte(record.Password), []byte(user.Password))
		if err == nil {
			*user = record
		} else {
			err = fmt.Errorf("wrong password: %v: %w", user.Username, err)
		}
	case strings.HasPrefix(record.Password, "$argon2id$"):
		ms := argon2idRegex.FindStringSubmatch(record.Password)
		if ms == nil {
			err = fmt.Errorf("invalid argon2id password: %v", record.Password)
			return
		}
		m, t, p := first(strconv.Atoi(ms[2])), first(strconv.Atoi(ms[3])), first(strconv.Atoi(ms[4]))
		var salt, key []byte
		salt, err = base64.RawStdEncoding.Strict().DecodeString(ms[5])
		if err != nil {
			err = fmt.Errorf("invalid argon2id password: %v : %w", record.Password, err)
			return
		}
		key, err = base64.RawStdEncoding.Strict().DecodeString(ms[6])
		if err != nil {
			err = fmt.Errorf("invalid argon2id password: %v : %w", record.Password, err)
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

	onceloader sync.Once
	fileloader *FileLoader[map[string]AuthUserInfo]
}

var authfileloaders = xsync.NewMap[string, *FileLoader[map[string]AuthUserInfo]]()

func (loader *AuthUserFileLoader) LoadAuthUsers(ctx context.Context) (map[string]AuthUserInfo, error) {
	if loader.fileloader != nil {
		return *loader.fileloader.Load(), nil
	}

	loader.onceloader.Do(func() {
		filename, _ := filepath.Abs(filepath.Clean(loader.Filename))
		loader.fileloader, _ = authfileloaders.LoadOrCompute(filename, func() (*FileLoader[map[string]AuthUserInfo], bool) {
			return &FileLoader[map[string]AuthUserInfo]{
				Filename:     loader.Filename,
				Unmarshal:    loader.Unmarshal,
				Logger:       cmp.Or(loader.Logger, slog.Default()),
				PollDuration: 15 * time.Second,
			}, false
		})
	})

	return *loader.fileloader.Load(), nil
}

/*

username,password,speed_limit,allow_tunnel,allow_client,allow_ssh,allow_webdav
foo,123456,-1,1,0,0,0
bar,qwerty,0,0,1,0,0

*/

func AuthUserFileCSVUnmarshaler(data []byte, v any) error {
	infos, ok := v.(*map[string]AuthUserInfo)
	if !ok {
		return fmt.Errorf("*map[string]AuthUserInfo required, found %T", v)
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
		if *infos == nil {
			*infos = make(map[string]AuthUserInfo)
		}
		(*infos)[user.Username] = user
	}

	return nil
}

/*

{"username":"foo","password":"123456","attrs":{"speed_limit":"-1","allow_tunnel":"0","allow_client":"0"}}
{"username":"bar","qwerty":"123456","attrs":{"speed_limit":"0","allow_tunnel":"0","allow_client":"1"}}

*/

func AuthUserFileJSONUnmarshaler(data []byte, v any) error {
	infos, ok := v.(*map[string]AuthUserInfo)
	if !ok {
		return fmt.Errorf("*map[string]AuthUserInfo required, found %T", v)
	}

	for line := range bytes.Lines(data) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var user AuthUserInfo
		err := json.Unmarshal(line, &user)
		if err != nil {
			return err
		}
		if *infos == nil {
			*infos = make(map[string]AuthUserInfo)
		}
		(*infos)[user.Username] = user
	}

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

func (loader *AuthUserCommandLoader) LoadAuthUsers(ctx context.Context) (map[string]AuthUserInfo, error) {
	if loader.CacheTTL > 0 {
		if ts := loader.mtime.Load(); 0 < ts && ts+int64(loader.CacheTTL) < time.Now().UnixNano() {
			return loader.users.Load().(map[string]AuthUserInfo), nil
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

	users := make(map[string]AuthUserInfo)
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
