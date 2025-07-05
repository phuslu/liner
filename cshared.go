package main

/*
	env CGO_ENABLED=1 go build -v -buildmode=c-shared -o libliner.so
	python -c 'import ctypes; ctypes.CDLL("./libliner.so").Main(b"phuslu.yaml")'
*/

import (
	"C"
)

//export Start
func Start(filename *C.char) {
	Main(C.GoString(filename))
}
