package main

/*
	env CGO_ENABLED=1 go build -v -buildmode=c-shared -o liner.so
	python3 -c 'import ctypes; ctypes.CDLL("./liner.so").Start()' <office.yaml
*/

import (
	"C"
)

//export Start
func Start() {
	main()
}
