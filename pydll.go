//go:build windows

// CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC="zig cc -target x86_64-windows-gnu" go build -v -trimpath -ldflags="-s -w" -buildmode=c-shared -o liner.dll

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
