package main

/*
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

PyMODINIT_FUNC PyInit_liner(void) {
    return PyModule_Create(&mod);
}
*/
import "C"
