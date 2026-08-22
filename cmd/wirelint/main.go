package main

import (
	"os"

	"github.com/Raskinkamar/WireLinter/internal/cli"
)

func main() {
	os.Exit(cli.RunFriendly(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
