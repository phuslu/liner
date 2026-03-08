package main

/*
#include <Python.h>
*/
import "C"

//export liner
func liner() *C.PyObject {
	main()
	C.Py_IncRef(C.Py_None)
	return C.Py_None
}
