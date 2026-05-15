package gosh

import (
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
)

func goshDefaultShell() string {
	if exe, err := exec.LookPath("bash"); err == nil {
		return exe
	}
	switch runtime.GOOS {
	case "windows":
		return "cmd.exe"
	default:
		return "/bin/sh"
	}
}

func goshEnvironWithDefaultShell(env []string) []string {
	if env == nil {
		env = os.Environ()
	}
	env = slices.Clone(env)
	if _, ok := goshLookupEnv(env, "SHELL"); !ok {
		env = append(env, "SHELL="+goshDefaultShell())
	}
	return env
}

func goshLookupEnv(env []string, key string) (string, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		name, value, ok := strings.Cut(env[i], "=")
		if !ok {
			continue
		}
		if name == key || runtime.GOOS == "windows" && strings.EqualFold(name, key) {
			return value, true
		}
	}
	return "", false
}

func goshExpandEnv(env []string, s string) string {
	return os.Expand(s, func(key string) string {
		value, _ := goshLookupEnv(env, key)
		return value
	})
}

func goshResolveInitFile(env []string, interactive bool) string {
	file, ok := goshLookupEnv(env, "GOSH_ENV")
	if !ok && interactive {
		file = "$HOME/.bashrc"
	}
	if file == "" {
		return ""
	}
	return goshExpandEnv(env, file)
}

func SetEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		name, _, ok := strings.Cut(env[i], "=")
		if !ok {
			continue
		}
		if name == key || runtime.GOOS == "windows" && strings.EqualFold(name, key) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}
