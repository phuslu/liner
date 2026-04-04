//go:build windows

package main

import (
	"context"
	"os"

	"github.com/phuslu/log"
)

import "C"

//export liner
func liner() {
	main()
}

//export linex
func linex() {
	gosh(context.Background(), log.IsTerminal(os.Stdin.Fd()), os.Stdin, os.Stdout, os.Stderr)
}
