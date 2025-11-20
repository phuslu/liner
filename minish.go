package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func minish() {
	fd := int(os.Stdin.Fd())

	oldState, err := term.GetState(fd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: not running in a terminal")
		return
	}

	runner, err := interp.New(interp.StdIO(os.Stdin, os.Stdout, os.Stderr))
	if err != nil {
		panic(err)
	}

	parser := syntax.NewParser()

	term.MakeRaw(fd)
	screen := term.NewTerminal(os.Stdin, "minish$ ")

	defer term.Restore(fd, oldState)

	for {
		line, err := screen.ReadLine()
		if err == io.EOF {
			return // Ctrl+D
		}
		if err != nil {
			fmt.Fprintf(screen, "Error: %v\n", err)
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" {
			return
		}

		prog, err := parser.Parse(strings.NewReader(line), "")
		if err != nil {
			fmt.Fprintf(screen, "Syntax error: %v\n", err)
			continue
		}

		term.Restore(fd, oldState)

		err = runner.Run(context.Background(), prog)

		if err != nil {
			if _, ok := interp.IsExitStatus(err); !ok {
				fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
			}
		}

		term.MakeRaw(fd)
	}
}
