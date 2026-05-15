package main

import (
	"os"

	"github.com/phuslu/pty"

	"liner/gosh"
)

var version = "0.0.0"

func main() {
	err := gosh.Run(gosh.Config{
		Args:                           os.Args,
		Stdin:                          os.Stdin,
		Stdout:                         os.Stdout,
		Stderr:                         os.Stderr,
		IsTerminal:                     pty.IsTerminal(os.Stdin.Fd()) && pty.IsTerminal(os.Stderr.Fd()),
		NotifySignals:                  true,
		Version:                        version,
		EnableVirtualTerminalSequences: pty.EnableVirtualTerminal,
	})
	if err != nil {
		os.Exit(gosh.ExitCode(err))
	}
}
