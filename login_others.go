//go:build !linux

package main

import (
	"errors"
	"fmt"
	"os"
)

func login() int {
	fmt.Fprintln(os.Stderr, "login:", errors.ErrUnsupported)
	return 1
}
