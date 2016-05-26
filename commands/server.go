package commands

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/go-cwe-dictionary/config"
	"github.com/kotakanbe/go-cwe-dictionary/db"
	"github.com/kotakanbe/go-cwe-dictionary/log"
	"github.com/kotakanbe/go-cwe-dictionary/server"
	"golang.org/x/net/context"
)

// ServerCmd is Subcommand for CVE dictionary HTTP Server
type ServerCmd struct {
	debug    bool
	debugSQL bool

	dbpath string
	bind   string
	port   string
}

// Name return subcommand name
func (*ServerCmd) Name() string { return "server" }

// Synopsis return synopsis
func (*ServerCmd) Synopsis() string { return "Start CWE dictionary HTTP server" }

// Usage return usage
func (*ServerCmd) Usage() string {
	return `server:
	server
		[-bind=127.0.0.1]
		[-port=1324]
		[-dbpath=$PWD/cwe.sqlite3]
		[-debug]
		[-debug-sql]

`
}

// SetFlags set flag
func (p *ServerCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.debug, "debug", false,
		"debug mode (default: false)")
	f.BoolVar(&p.debugSQL, "debug-sql", false,
		"SQL debug mode (default: false)")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.dbpath, "dbpath", pwd+"/cwe.sqlite3",
		fmt.Sprintf("/path/to/sqlite3"))

	f.StringVar(&p.bind,
		"bind",
		"127.0.0.1",
		"HTTP server bind to IP address (default: loop back interface)")
	f.StringVar(&p.port, "port", "1324",
		"HTTP server port number (default: 1324)")
}

// Execute execute
func (p *ServerCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	c.Conf.Debug = p.debug
	c.Conf.DebugSQL = p.debugSQL

	if c.Conf.Debug {
		log.SetDebug()
	}

	c.Conf.Bind = p.bind
	c.Conf.Port = p.port
	c.Conf.DBPath = p.dbpath

	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	if _, err := os.Stat(c.Conf.DBPath); os.IsNotExist(err) {
		log.Errorf("SQLite3 file not exists. Check the dbpath or execute below command to fetch CWE data before running as servermode. dbpath: %s", c.Conf.DBPath)
		log.Errorf("  $ go-cwe-dictionary fetch")
		return subcommands.ExitFailure
	}

	log.Infof("Opening DB. datafile: %s", c.Conf.DBPath)
	if err := db.OpenDB(c.Conf); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}

	count, err := db.CountCwe()
	if err != nil {
		log.Errorf("Failed to count NVD table: %s", err)
		return subcommands.ExitFailure
	}

	if count == 0 {
		log.Info("No CWE data found. Run the below command to fetch CWE data")
		log.Info("")
		log.Info(" go-cwe-dictionary fetch")
		log.Info("")
		return subcommands.ExitFailure
	}

	log.Info("Starting HTTP Server...")
	if err := server.Start(); err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
