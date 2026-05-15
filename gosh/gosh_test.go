package gosh

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
)

func testEnv(t *testing.T) []string {
	t.Helper()
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"HISTFILE=" + os.DevNull,
	}
}

func TestRunCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(Config{
		Args:    []string{"gosh", "-c", `printf '%s:%s' "$0" "$1"`, "argv0", "param1"},
		Stdout:  &stdout,
		Stderr:  &stderr,
		Env:     testEnv(t),
		Version: "1.2.3",
	})
	if err != nil {
		t.Fatalf("Run -c failed: %v\nstderr: %s", err, stderr.String())
	}
	if got, want := stdout.String(), "argv0:param1"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestRunNonInteractiveStdin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(Config{
		Args:    []string{"gosh"},
		Stdin:   strings.NewReader("read value; printf '<%s>' \"$value\"\nfrom-stdin\n"),
		Stdout:  &stdout,
		Stderr:  &stderr,
		Env:     testEnv(t),
		Version: "1.2.3",
	})
	if err != nil {
		t.Fatalf("Run stdin failed: %v\nstderr: %s", err, stderr.String())
	}
	if got, want := stdout.String(), "<from-stdin>"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestExitCode(t *testing.T) {
	if got := ExitCode(nil); got != 0 {
		t.Fatalf("ExitCode(nil) = %d, want 0", got)
	}
	status := interp.ExitStatus(42)
	if !IsExitStatus(status) {
		t.Fatalf("IsExitStatus(interp.ExitStatus) = false")
	}
	if got := ExitCode(status); got != 42 {
		t.Fatalf("ExitCode(interp.ExitStatus) = %d, want 42", got)
	}
	if got := ExitCode(context.Canceled); got != 130 {
		t.Fatalf("ExitCode(context.Canceled) = %d, want 130", got)
	}
	if got := ExitCode(os.ErrInvalid); got != 127 {
		t.Fatalf("ExitCode(other) = %d, want 127", got)
	}
}

func TestSetEnv(t *testing.T) {
	env := []string{"A=1", "B=2", "A=3"}
	env = SetEnv(env, "A", "4")
	if want := []string{"A=1", "B=2", "A=4"}; !reflect.DeepEqual(env, want) {
		t.Fatalf("SetEnv update = %#v, want %#v", env, want)
	}
	env = SetEnv(env, "C", "5")
	if want := []string{"A=1", "B=2", "A=4", "C=5"}; !reflect.DeepEqual(env, want) {
		t.Fatalf("SetEnv append = %#v, want %#v", env, want)
	}
}

func TestHistoryEncodingAndControl(t *testing.T) {
	for _, line := range []string{
		"echo plain",
		"echo one\necho two",
		goshHistoryEncodedPrefix + "literal",
	} {
		if got := goshDecodeHistoryLine(goshEncodeHistoryLine(line)); got != line {
			t.Fatalf("history roundtrip = %q, want %q", got, line)
		}
	}

	history := &goshHistory{limit: 10, control: goshParseHistoryControl("ignoreboth")}
	if history.Add(" leading-space") {
		t.Fatalf("history saved ignorespace entry")
	}
	if !history.Add("echo ok") {
		t.Fatalf("history did not save first entry")
	}
	if history.Add("echo ok") {
		t.Fatalf("history saved duplicate entry")
	}
	if got, want := history.Entries(), []string{"echo ok"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("history entries = %#v, want %#v", got, want)
	}
}

func TestBindParser(t *testing.T) {
	key, action, err := goshParseBindArgs([]string{`"\e[A": history-search-backward`})
	if err != nil {
		t.Fatalf("goshParseBindArgs failed: %v", err)
	}
	if key != `"\e[A"` || action != "history-search-backward" {
		t.Fatalf("bind args = %q, %q", key, action)
	}
	seq, err := goshParseKeySequence(key)
	if err != nil {
		t.Fatalf("goshParseKeySequence failed: %v", err)
	}
	if want := []byte{0x1b, '[', 'A'}; !reflect.DeepEqual(seq, want) {
		t.Fatalf("key sequence = %#v, want %#v", seq, want)
	}
	if got, ok := goshLookupBindAction(action); !ok || got != goshKeyActionHistorySearchBackward {
		t.Fatalf("bind action = %v, %v", got, ok)
	}
}

func TestCompletionHelpers(t *testing.T) {
	ctx := goshScanCompletionContext([]rune("cd ~/Do"))
	if ctx.isCommand || ctx.command != "cd" || ctx.prefix != "~/Do" {
		t.Fatalf("completion context = %#v", ctx)
	}
	if got, want := goshEscapeCompletionForContext("a b$", 0), `a\ b\$`; got != want {
		t.Fatalf("escaped completion = %q, want %q", got, want)
	}
	if got, want := goshEscapeCompletionForContext(`a"$`, '"'), `a\"\$`; got != want {
		t.Fatalf("double-quoted completion = %q, want %q", got, want)
	}
	if got, want := goshLongestCommonPrefix([]string{"alpha", "alpine"}), "alp"; got != want {
		t.Fatalf("longest common prefix = %q, want %q", got, want)
	}
	expanded, ok := goshExpandTilde("~/src", "/home/tester")
	if !ok || expanded != filepath.Join("/home/tester", "src") {
		t.Fatalf("goshExpandTilde = %q, %v", expanded, ok)
	}
}

func TestPromptRenderer(t *testing.T) {
	state := &goshPromptState{
		vars:      map[string]string{"USER": "alice", "HOME": "/home/alice"},
		dir:       "/home/alice/project",
		host:      "host.example",
		shortHost: "host",
		seq:       3,
		now:       time.Date(2026, 5, 15, 9, 8, 7, 0, time.UTC),
	}
	got := (&goshPromptRenderer{src: `\u@\h:\w \D{%F} \# \$`, state: state}).render()
	want := "alice@host:~/project 2026-05-15 3 " + state.promptSymbol()
	if got != want {
		t.Fatalf("prompt = %q, want %q", got, want)
	}
	if got := goshDefaultPrompt(""); !strings.HasPrefix(got, "sh-0.0") {
		t.Fatalf("empty-version prompt = %q", got)
	}
}

func TestShellOptionVersion(t *testing.T) {
	env := &goshShellEnviron{
		base:    expand.ListEnviron("X=1"),
		flags:   func() string { return "hBs" },
		version: "1.2.3",
	}
	if got := env.Get("-").String(); got != "hBs" {
		t.Fatalf("$- = %q, want hBs", got)
	}
	if got := env.Get("BASH_VERSION").String(); got != "1.2.3(1)-gosh" {
		t.Fatalf("BASH_VERSION = %q", got)
	}
}
