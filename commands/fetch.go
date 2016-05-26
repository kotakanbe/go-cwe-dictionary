package commands

import (
	"flag"
	"os"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/go-cwe-dictionary/config"
	"github.com/kotakanbe/go-cwe-dictionary/cwe"
	"github.com/kotakanbe/go-cwe-dictionary/db"
	log "github.com/kotakanbe/go-cwe-dictionary/log"
	"github.com/kotakanbe/go-cwe-dictionary/models"
	"golang.org/x/net/context"
)

// FetchCmd is Subcommand for fetch Nvd information.
type FetchCmd struct {
	debug     bool
	debugSQL  bool
	dbpath    string
	httpProxy string
}

// Name return subcommand name
func (*FetchCmd) Name() string { return "fetch" }

// Synopsis return synopsis
func (*FetchCmd) Synopsis() string { return "Fetch CWE" }

// Usage return usage
func (*FetchCmd) Usage() string {
	return `fetch:
	fetch
		[-dbpath=/path/to/cwe.sqlite3]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
`
}

// SetFlags set flag
func (p *FetchCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.debug, "debug", false,
		"debug mode")
	f.BoolVar(&p.debugSQL, "debug-sql", false,
		"SQL debug mode")

	pwd := os.Getenv("PWD")
	f.StringVar(&p.dbpath, "dbpath", pwd+"/cwe.sqlite3", "/path/to/sqlite3")

	f.StringVar(
		&p.httpProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)
}

// Execute execute
func (p *FetchCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	c.Conf.Debug = true
	c.Conf.DebugSQL = p.debugSQL

	if c.Conf.Debug {
		log.SetDebug()
	}

	c.Conf.DBPath = p.dbpath
	c.Conf.HTTPProxy = p.httpProxy

	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	if _, err := os.Stat(c.Conf.DBPath); err == nil {
		log.Errorf("SQLite3 file already exists. Remove it or specify -dbpath. path: %s", c.Conf.DBPath)
		return subcommands.ExitFailure
	}

	log.Infof("Fetching CWE data...")
	weeknessCatalog, err := cwe.FetchCWE(c.Conf.HTTPProxy)
	if err != nil {
		log.Errorf("Failed to fetch CWE data. err: %s", err)
		return subcommands.ExitFailure
	}
	cwes := models.ConvertToModel(weeknessCatalog)

	log.Infof("Inserting into DB... dbpath: %s", c.Conf.DBPath)
	if err := db.Init(c.Conf); err != nil {
		log.Errorf("Failed to Init DB. err: %s", err)
		return subcommands.ExitFailure
	}

	if err := db.InsertCwes(cwes, c.Conf); err != nil {
		log.Errorf("Failed to inserting DB. err: %s", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
