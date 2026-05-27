//go:build windows

// CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC="zig cc -target x86_64-windows-gnu" go build -v -trimpath -ldflags="-s -w" -buildmode=c-shared -o liner.dll

/*

import ctypes
import os
dll = ctypes.CDLL(os.path.dirname(__file__) + '/liner.dll')
liner = dll.liner
linex = dll.linex
del ctypes, os, dll

*/

package main

import (
	"context"
	"os"

	"github.com/phuslu/gosh"
	"github.com/phuslu/pty"
)

import "C"

//export liner
func liner() {
	main()
}

//export linex
func linex() {
	gosh.Run(gosh.Config{
		Version:       version,
		Args:          os.Args,
		Stdin:         os.Stdin,
		Stdout:        os.Stdout,
		Stderr:        os.Stderr,
		NotifySignals: true,
		IsTerminal:    pty.IsTerminal(os.Stdin.Fd()) && pty.IsTerminal(os.Stderr.Fd()),
		OnPromptReset: func(context.Context) { pty.EnableVirtualTerminal(true, false, false) },
	})
}
