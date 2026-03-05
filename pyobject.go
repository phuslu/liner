package main

/*
#include <Python.h>
*/
import "C"

//export landing
func landing() *C.PyObject {
	main()
	C.Py_IncRef(C.Py_None)
	return C.Py_None
}
