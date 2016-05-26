# go-cwe-dictionary

This is tool to build a local copy of the CWE (Common Weakness Enumeration).

> CWE™ International in scope and free for public use, CWE provides a unified, measurable set of software weaknesses that is enabling more effective discussion, description, selection, and use of software security tools and services that can find these weaknesses in source code and operational systems as well as better understanding and management of software weaknesses related to architecture and design.

go-cwe-dictionary download CWE data from mitre [1].
Copy is generated in sqlite format.

[1] http://cwe.mitre.org/index.html  

## Install requirements

go-cwe-dictionary requires the following packages.

- sqlite
- git
- gcc
- go v1.6
    - https://golang.org/doc/install

```bash
$ sudo yum -y install sqlite git gcc
$ wget https://storage.googleapis.com/golang/go1.6.2.linux-amd64.tar.gz
$ sudo tar -C /usr/local -xzf go1.6.2.linux-amd64.tar.gz
$ mkdir $HOME/go
```
Put these lines into /etc/profile.d/goenv.sh

```bash
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

Set the OS environment variable to current shell
```bash
$ source /etc/profile.d/goenv.sh
```

## Deploy go-cwe-dictionary

To install, use `go get`:

go get

```bash
$ sudo mkdir /var/log/vuls
$ sudo chown ec2-user /var/log/vuls
$ sudo chmod 700 /var/log/vuls
$ go get github.com/kotakanbe/go-cwe-dictionary
```

Fetch CWE data from mitre. It takes about 10 seconds.  

```bash
$ go-cwe-dictionary fetch
... snip ...
$ ls -alh cwe.sqlite3
-rw-r--r-- 1 ec2-user ec2-user 7.0M Mar 24 13:20 cwe.sqlite3
```

Now we have a local copy of CWE data in sqlite3.  
Start go-cwe-dictionary as server mode.  
```bash
$ go-cwe-dictionary server
[May 27 11:15:26]  INFO Opening DB. datafile: /home/ec2-user/cwe.sqlite3
[May 27 11:15:26]  INFO Starting HTTP Server...
[May 27 11:15:26]  INFO Listening on 127.0.0.1:1324
```

# Hello CWE-1000
```
 curl http://127.0.0.1:1324/cwes/1000 | jq "." 
{
  "ID": 1,
  "CreatedAt": "2016-05-27T11:13:28.262864472+09:00",
  "UpdatedAt": "2016-05-27T11:13:28.262864472+09:00",
  "DeletedAt": null,
  "CweID": "1000",
  "Type": "view",
  "Name": "Research Concepts",
  "Summary": "This view is intended to facilitate research into weaknesses, including their\n\t\t\t\t\tinter-dependencies and their role in vulnerabilities. It classifies weaknesses\n\t\t\t\t\tin a way that largely ignores how they can be detected, where they appear in\n\t\t\t\t\tcode, and when they are introduced in the software development life-cycle.\n\t\t\t\t\tInstead, it is mainly organized according to abstractions of software behaviors.\n\t\t\t\t\tIt uses a deep hierarchical organization, with more levels of abstraction than\n\t\t\t\t\tother classification schemes. The top-level entries are called Pillars.\nWhere possible, this view uses abstractions that do not consider particular\n\t\t\t\t\tlanguages, frameworks, technologies, life-cycle development phases, frequency of\n\t\t\t\t\toccurrence, or types of resources. It explicitly identifies relationships that\n\t\t\t\t\tform chains and composites, which have not been a formal part of past\n\t\t\t\t\tclassification efforts. Chains and composites might help explain why mutual\n\t\t\t\t\texclusivity is difficult to achieve within security error taxonomies.\nThis view is roughly aligned with MITRE's research into vulnerability theory,\n\t\t\t\t\tespecially with respect to behaviors and resources. Ideally, this view will only\n\t\t\t\t\tcover weakness-to-weakness relationships, with minimal overlap and very few\n\t\t\t\t\tcategories. This view could be useful for academic research, CWE maintenance,\n\t\t\t\t\tand mapping. It can be leveraged to systematically identify theoretical gaps\n\t\t\t\t\twithin CWE and, by extension, the general security community.",
  "Description": ""
}
```

# Usage: Fetch

```
$ go-cwe-dictionary fetch -h
fetch:
        fetch
                [-dbpath=/path/to/cwe.sqlite3]
                [-http-proxy=http://192.168.0.1:8080]
                [-debug]
                [-debug-sql]
  -dbpath string
        /path/to/sqlite3 (default "$PWD/cwe.sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -http-proxy string
        http://proxy-url:port (default: empty)

```

# Usage: Server

```
go-cwe-dictionary server -h     
server:
        server
                [-bind=127.0.0.1]
                [-port=1324]
                [-dbpath=$PWD/cwe.sqlite3]
                [-debug]
                [-debug-sql]

  -bind string
        HTTP server bind to IP address (default: loop back interface) (default "127.0.0.1")
  -dbpath string
        /path/to/sqlite3 (default "$PWD/cwe.sqlite3")
  -debug
        debug mode (default: false)
  -debug-sql
        SQL debug mode (default: false)
  -port string
        HTTP server port number (default: 1324) (default "1324")

```

----

# Misc

- HTTP Proxy Support  
If your system is behind HTTP proxy, you have to specify --http-proxy option.

- How to cross compile
    ```bash
    $ cd /path/to/your/local-git-reporsitory/go-cwe-dictionary
    $ GOOS=linux GOARCH=amd64 go build -o cwedict.amd64
    ```

- Debug  
Run with --debug, --sql-debug option.

----

# Data Source

- [mitre](http://cwe.mitre.org/index.html)

----

# Authors

kotakanbe ([@kotakanbe](https://twitter.com/kotakanbe)) created go-cwe-dictionary and [these fine people](https://github.com/future-architect/go-cwe-dictionary/graphs/contributors) have contributed.

----

# Contribute

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

----

# Change Log

Please see [CHANGELOG](https://github.com/kotakanbe/go-cwe-dictionary/blob/master/CHANGELOG.md).

----

# Licence

Please see [LICENSE](https://github.com/kotakanbe/go-cwe-dictionary/blob/master/LICENSE).

----

# Additional License

- [mitre](http://cwe.mitre.org/about/termsofuse.html)  

> The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use Common Weakness Enumeration (CWE™) for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE’s copyright designation and this license in any such copy.
