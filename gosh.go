package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

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

	if filename := os.Getenv("GOSH_ENV"); filename != "" {
		if file, err := os.Open(filename); err == nil {
			prog, err := parser.Parse(file, filename)
			if err != nil {
				fmt.Fprintln(stderr, "failed to parse ", filename, ":", err)
			} else {
				if err := runner.Run(ctx, prog); err != nil {
					fmt.Fprintln(stderr, "failed to run ", filename, ":", err)
				}
			}
			file.Close()
		} else {
			fmt.Fprintln(stderr, "failed to open ", filename, ":", err)
		}
	}

	prompt := "$"
	if os.Geteuid() == 0 {
		prompt = "#"
	}

	if isatty {
		fmt.Fprint(stdout, prompt+" ")
		return parser.Interactive(stdin, func(stmts []*syntax.Stmt) bool {
			for _, stmt := range stmts {
				err := runner.Run(ctx, stmt)
				if err != nil {
					fmt.Fprintln(stdout, err.Error())
				}
				if runner.Exited() {
					return false
				}
			}
			fmt.Fprint(stdout, prompt+" ")
			return true
		})
	} else {
		prog, err := parser.Parse(stdin, "")
		if err != nil {
			return err
		}
		runner.Reset()
		return runner.Run(ctx, prog)
	}
}
