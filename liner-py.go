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
	gosh(context.Background(), log.IsTerminal(os.Stdin.Fd()), os.Stdin, os.Stdout, os.Stderr)
	C.Py_IncRef(C.Py_None)
	return C.Py_None
}

//export PyInit_liner
func PyInit_liner() *C.PyObject {
	return C.PyModule_Create_Liner()
}
