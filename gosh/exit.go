package gosh

import (
	"context"
	"errors"

	"mvdan.cc/sh/v3/interp"
)

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var status interp.ExitStatus
	if errors.As(err, &status) {
		return int(status)
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	return 127
}

func IsExitStatus(err error) bool {
	var status interp.ExitStatus
	return errors.As(err, &status)
}
