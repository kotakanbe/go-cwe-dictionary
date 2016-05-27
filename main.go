package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/net/context"

	"github.com/google/subcommands"
	"github.com/kotakanbe/go-cwe-dictionary/commands"
	"github.com/kotakanbe/go-cwe-dictionary/version"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&commands.ServerCmd{}, "server")
	subcommands.Register(&commands.FetchCmd{}, "fetch")

	var v = flag.Bool("v", false, "Show version")

	flag.Parse()

	if *v {
		fmt.Printf("%s %s\n", version.Name, version.Version)
		os.Exit(int(subcommands.ExitSuccess))
	}

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
