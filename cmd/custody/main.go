// Command custody is the operator-facing CLI for interactive identity flows.
package main

import (
	"fmt"
	"io"
	"os"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if len(args) == 1 && args[0] == "login" {
		return runLogin(stdout, stderr)
	}

	fmt.Fprintln(stderr, "custody: zero-trust authorization across a request chain")
	fmt.Fprintln(stderr, "usage: custody version | login")
	if len(args) > 0 {
		return 2
	}
	return 0
}
