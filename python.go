package main

/*
#include <Python.h>

extern PyObject* say();

static PyMethodDef methods[] = {
    {"say", (PyCFunction)say, METH_NOARGS, ""},
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
