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
	"os"
)

import "C"

//export liner
func liner() {
	main()
}

//export linex
func linex() {
	gosh(os.Stdin, os.Stdout, os.Stderr)
}
