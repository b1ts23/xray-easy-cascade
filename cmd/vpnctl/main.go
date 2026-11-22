// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"os"

	"github.com/b1ts23/xray-easy-cascade/internal/command"
)

func main() {
	if err := command.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(command.ExitCode(err))
	}
}
