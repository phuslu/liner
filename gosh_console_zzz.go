//go:build !windows

package main

import "io"

func goshInteractiveUIWriter(stderr io.Writer) io.Writer {
	if stderr == nil {
		return io.Discard
	}
	return stderr
}
