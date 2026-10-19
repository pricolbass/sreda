package main

import (
	"fmt"
	"os"

	"sreda/internal/command"
)

func main() {
	if err := command.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
