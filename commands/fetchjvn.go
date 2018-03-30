package commands

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/subcommands"
	c "github.com/kotakanbe/go-cwe-dictionary/config"
	"github.com/kotakanbe/go-cwe-dictionary/golang"
	log "github.com/kotakanbe/go-cwe-dictionary/log"
	"github.com/kotakanbe/go-cwe-dictionary/models"
	"golang.org/x/net/context"

	jvn "github.com/kotakanbe/go-cve-dictionary/fetcher/jvn/xml"
	cvedictlog "github.com/kotakanbe/go-cve-dictionary/log"
	jvnmodels "github.com/kotakanbe/go-cve-dictionary/models"
)

// FetchJVNCmd is Subcommand for fetch Nvd information.
type FetchJVNCmd struct {
	debug     bool
	debugSQL  bool
	dbpath    string
	httpProxy string
	goconst   bool
	sqlite3   bool
}

// Name return subcommand name
func (*FetchJVNCmd) Name() string { return "fetchjvn" }

// Synopsis return synopsis
func (*FetchJVNCmd) Synopsis() string { return "Fetch CWE" }

// Usage return usage
func (*FetchJVNCmd) Usage() string {
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
func (p *FetchJVNCmd) SetFlags(f *flag.FlagSet) {
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
func (p *FetchJVNCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

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

	cvedictlog.Initialize("/tmp", p.debug, os.Stderr)

	urls := []string{}
	thisYear := time.Now().Year()
	for i := 1998; i <= thisYear; i++ {
		url := fmt.Sprintf("https://jvndb.jvn.jp/ja/rss/years/jvndb_%d.rdf", i)
		urls = append(urls, url)
	}
	urls = append(urls,
		"https://jvndb.jvn.jp/ja/rss/jvndb.rdf",
		"https://jvndb.jvn.jp/ja/rss/jvndb_new.rdf")

	needUpdates := []jvnmodels.FeedMeta{}
	for _, u := range urls {
		needUpdates = append(needUpdates, jvnmodels.FeedMeta{URL: u})
	}
	items, err := jvn.Fetch(needUpdates)
	if err != nil {
		log.Errorf("Failed to fetch JVN: %s", err)
		return subcommands.ExitUsageError
	}

	cwes := models.ConvertToModelJVN(items)
	code, err := golang.GenerateJVN(cwes.Uniq())
	if err != nil {
		log.Error(err)
		return subcommands.ExitFailure
	}
	fmt.Println(code)

	return subcommands.ExitSuccess
}
