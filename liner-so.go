//go:build !windows

// CGO_ENABLED=1 CGO_CFLAGS="$(python3-config --includes)" CGO_LDFLAGS="$(python3-config --ldflags)" go build -v -trimpath -ldflags="-s -w" -buildmode=c-shared -o liner.so

package main

import (
	"context"
	"os"

	"github.com/phuslu/log"
)

/*
#define Py_LIMITED_API 0x03020000
#include <Python.h>
*/
import "C"

//export liner
func liner() *C.PyObject {
	main()
	C.Py_IncRef(C.Py_None)
	return C.Py_None
}

//export linex
func linex() *C.PyObject {
	gosh(context.Background(), log.IsTerminal(os.Stdin.Fd()), os.Stdin, os.Stdout, os.Stderr)
	C.Py_IncRef(C.Py_None)
	return C.Py_None
}
