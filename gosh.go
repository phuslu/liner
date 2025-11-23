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

	runner, err := interp.New(interp.Interactive(true), interp.StdIO(stdin, stdout, stderr))
	if err != nil {
		return err
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
