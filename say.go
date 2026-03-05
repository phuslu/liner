package main

/*
#include <Python.h>
*/
import "C"

//export say
func say() *C.PyObject {
	main()
	return C.PyUnicode_FromString(C.CString("hello"))
}
