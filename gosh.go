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

func gosh(stdin io.Reader, stdout, stderr io.Writer) error {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	r, err := interp.New(interp.Interactive(true), interp.StdIO(stdin, stdout, stderr))
	if err != nil {
		return err
	}

	parser := syntax.NewParser()
	fmt.Fprintf(stdout, "$ ")

	parser.Interactive(stdin, func(stmts []*syntax.Stmt) bool {
		for _, stmt := range stmts {
			err := r.Run(ctx, stmt)
			if err != nil {
				fmt.Fprintln(stdout, err.Error())
			}
			if r.Exited() {
				return false
			}
		}
		fmt.Fprintf(stdout, "$ ")
		return true
	})

	return nil
}
