package commands

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/go-cwe-dictionary/config"
	"github.com/kotakanbe/go-cwe-dictionary/cwe"
	"github.com/kotakanbe/go-cwe-dictionary/db"
	"github.com/kotakanbe/go-cwe-dictionary/golang"
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
	goconst   bool
	sqlite3   bool
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
		[-sqlite3]
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
	f.BoolVar(&p.sqlite3, "sqlite3", false,
		"Print Go Const definition to stdout")
	f.BoolVar(&p.goconst, "go", true,
		"Print Go Const definition to stdout")

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

	log.Infof("Fetching CWE data...")
	weeknessCatalog, err := cwe.FetchCWE(c.Conf.HTTPProxy)
	if err != nil {
		log.Errorf("Failed to fetch CWE data. err: %s", err)
		return subcommands.ExitFailure
	}
	cwes := models.ConvertToModel(weeknessCatalog)

	if p.sqlite3 {
		if _, err := os.Stat(c.Conf.DBPath); err == nil {
			log.Errorf("SQLite3 file already exists. Remove it or specify -dbpath. path: %s", c.Conf.DBPath)
			return subcommands.ExitFailure
		}

		log.Infof("Inserting into DB... dbpath: %s", c.Conf.DBPath)
		if err := db.Init(c.Conf); err != nil {
			log.Errorf("Failed to Init DB. err: %s", err)
			return subcommands.ExitFailure
		}

		if err := db.InsertCwes(cwes, c.Conf); err != nil {
			log.Errorf("Failed to inserting DB. err: %s", err)
			return subcommands.ExitFailure
		}
	}

	if p.goconst {
		for i, c := range cwes {
			replacer := strings.NewReplacer(
				"\t", " ",
				"\n", "",
				"\r", "",
				"\"", "'",
				`\`, `\\`,
			)
			cwes[i].Name = strings.TrimSpace(replacer.Replace(c.Name))
			cwes[i].Description = strings.TrimSpace(replacer.Replace(c.Description))
			cwes[i].ExtendedDescription = strings.TrimSpace(replacer.Replace(c.ExtendedDescription))
		}
		code, err := golang.GenerateNVD(cwes)
		if err != nil {
			log.Error(err)
			return subcommands.ExitFailure
		}
		fmt.Println(code)
	}

	return subcommands.ExitSuccess
}
