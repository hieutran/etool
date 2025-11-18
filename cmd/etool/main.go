package main

import (
	"fmt"
	"os"

	"github.com/hieutran/etool/cmd/etool/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
