// Command fakegame stands in for ForgedAlliance.exe / main.exe in mpemu runs.
// It takes the game's own command line:
//
//	fakegame /gpgnet 127.0.0.1:<port> [/players N] [/log path] [other game args are ignored]
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"faf-main/tools/fakegame"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := fakegame.Run(ctx, fakegame.ParseArgs(os.Args[1:])); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
