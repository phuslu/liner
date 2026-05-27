//go:build !windows

// CGO_ENABLED=1 CGO_CFLAGS="$(python3-config --includes)" CGO_LDFLAGS="$(python3-config --ldflags)" go build -v -trimpath -ldflags="-s -w" -buildmode=c-shared -o liner.so

package main

import (
	"context"
	"os"
	"strings"

	"github.com/phuslu/gosh"
	"github.com/phuslu/pty"
)

/*
#define Py_LIMITED_API 0x03020000
#include <Python.h>

extern PyObject* liner();
extern PyObject* linex();

static PyMethodDef methods[] = {
    {"liner", (PyCFunction)liner, METH_NOARGS, ""},
    {"linex", (PyCFunction)linex, METH_NOARGS, ""},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef mod = {
    PyModuleDef_HEAD_INIT,
    "liner",
    NULL,
    -1,
    methods
};

static inline PyObject* PyModule_Create_Liner(void) {
    return PyModule_Create(&mod);
}
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
	args := strings.Split(strings.Join(os.Args, "\x00"), "\x00")
	SetProcessName(os.Args[0])
	gosh.Run(gosh.Config{
		Version:       version,
		Args:          args,
		Stdin:         os.Stdin,
		Stdout:        os.Stdout,
		Stderr:        os.Stderr,
		NotifySignals: true,
		IsTerminal:    pty.IsTerminal(os.Stdin.Fd()) && pty.IsTerminal(os.Stderr.Fd()),
		OnPromptReset: func(context.Context) { pty.EnableVirtualTerminal(true, false, false) },
	})
	C.Py_IncRef(C.Py_None)
	return C.Py_None
}

//export PyInit_liner
func PyInit_liner() *C.PyObject {
	return C.PyModule_Create_Liner()
}
