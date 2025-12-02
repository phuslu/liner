#define Py_LIMITED_API 0x03090000

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include "libliner.cp39.h"

static PyObject* start(PyObject *self, PyObject *args) {
    Start();
    Py_RETURN_NONE;
}

static PyMethodDef StartMethods[] = {
    {"start", start, METH_NOARGS, "start liner"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef startmodule = {
    PyModuleDef_HEAD_INIT,
    "liner",
    NULL,
    -1,
    StartMethods
};

PyMODINIT_FUNC PyInit_liner(void) {
    return PyModule_Create(&startmodule);
}
