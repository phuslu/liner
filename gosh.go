package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/chzyer/readline"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func gosh(ctx context.Context, isatty bool, stdin io.Reader, stdout, stderr io.Writer) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	parser := syntax.NewParser()
	runner, err := interp.New(
		interp.Interactive(true),
		interp.StdIO(stdin, stdout, stderr),
	)
	if err != nil {
		return err
	}

	// Source the init file specified by GOSH_ENV, if set.
	if filename := os.Getenv("GOSH_ENV"); filename != "" {
		if file, err := os.Open(filename); err == nil {
			prog, err := parser.Parse(file, filename)
			if err != nil {
				fmt.Fprintln(stderr, "failed to parse", filename, ":", err)
			} else {
				if err := runner.Run(ctx, prog); err != nil {
					fmt.Fprintln(stderr, "failed to run", filename, ":", err)
				}
			}
			file.Close()
		} else {
			fmt.Fprintln(stderr, "failed to open", filename, ":", err)
		}
	}

	mainPrompt := "$ "
	if os.Geteuid() == 0 {
		mainPrompt = "# "
	}

	// Non-interactive: parse stdin as a script and run it directly.
	if !isatty {
		prog, err := parser.Parse(stdin, "")
		if err != nil {
			return err
		}
		runner.Reset()
		return runner.Run(ctx, prog)
	}

	histFile := ""
	if home, err := os.UserHomeDir(); err == nil {
		histFile = home + "/.gosh_history"
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          mainPrompt,
		HistoryFile:     histFile,
		HistoryLimit:    1000,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		Stdout:          cmp.Or(stdout.(*os.File), os.Stdout),
		Stderr:          cmp.Or(stderr.(*os.File), os.Stderr),
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	// goshReader wraps readline so parser.Interactive can consume it as an
	// io.Reader. Each call to Read invokes Readline() to fetch one line.
	// Ctrl-C (ErrInterrupt) injects a newline to abandon the current
	// incomplete statement. Ctrl-D / EOF returns io.EOF to end the session.
	rdr := &goshReader{rl: rl}

	return parser.Interactive(rdr, func(stmts []*syntax.Stmt) bool {
		// parser.Incomplete() returns true when the parser has consumed a
		// partial statement and is waiting for more input (e.g. open quotes,
		// unclosed if/for blocks). Switch to the continuation prompt and keep
		// reading without executing anything yet.
		if parser.Incomplete() {
			rl.SetPrompt("> ")
			return true
		}

		// Restore the main prompt, updating it in case the effective UID
		// changed (e.g. via su).
		if os.Geteuid() == 0 {
			rl.SetPrompt("# ")
		} else {
			rl.SetPrompt("$ ")
		}

		for _, stmt := range stmts {
			if err := runner.Run(ctx, stmt); err != nil {
				fmt.Fprintln(rl.Stdout(), err.Error())
			}
			if runner.Exited() {
				return false
			}
		}
		return true
	})
}

// goshReader adapts *readline.Instance to the io.Reader interface expected by
// parser.Interactive. The parser calls Read whenever it needs more input.
type goshReader struct {
	rl  *readline.Instance
	buf []byte // leftover bytes from the previous Readline call
}

func (r *goshReader) Read(p []byte) (int, error) {
	// Drain any bytes that did not fit into p on the previous call.
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	line, err := r.rl.Readline()
	if err != nil {
		if err == readline.ErrInterrupt {
			// Ctrl-C: feed a bare newline so the parser discards the current
			// incomplete statement and returns to a clean state.
			p[0] = '\n'
			return 1, nil
		}
		// Ctrl-D or any other error: signal EOF to shut down the parser loop.
		return 0, io.EOF
	}

	data := []byte(line + "\n")
	n := copy(p, data)
	if n < len(data) {
		r.buf = data[n:] // stash the remainder for the next Read call
	}
	return n, nil
}
