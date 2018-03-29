package cwe

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/parnurzeal/gorequest"
)

// WeaknessCatalog has cwe items
// http://cwe.mitre.org/data/index.html
type WeaknessCatalog struct {
	Weaknesses []Weakness `xml:"Weaknesses>Weakness"`
}

// Weakness has CWE weakness item
type Weakness struct {
	ID                  string `xml:"ID,attr"`
	Name                string `xml:"Name,attr"`
	Description         string `xml:"Description"`
	ExtendedDescription string `xml:"Extended_Description"`
}

// FetchCWE fetches CWE archive
func FetchCWE(httpProxy string) (cwes WeaknessCatalog, err error) {
	var body string
	var errs []error
	var resp *http.Response
	url := "https://cwe.mitre.org/data/xml/cwec_v3.0.xml.zip"
	resp, body, errs = gorequest.New().Proxy(httpProxy).Get(url).End()

	if len(errs) > 0 || resp == nil || resp.StatusCode != 200 {
		return cwes, fmt.Errorf("HTTP error. errs: %v, url: %s", errs, url)
	}

	b := strings.NewReader(body)
	reader, err := zip.NewReader(b, b.Size())

	if err != nil {
		return cwes, fmt.Errorf(
			"Failed to decompress CWE feedfile. url: %s, err: %s", url, err)
	}

	for _, f := range reader.File {
		src, err := f.Open()
		if err != nil {
			return cwes, fmt.Errorf(
				"Failed to open CWE feedfile. url: %s, err: %s", url, err)
		}
		defer src.Close()

		bytes, err := ioutil.ReadAll(src)
		if err != nil {
			return cwes, fmt.Errorf(
				"Failed to Read NVD feedfile. url: %s, err: %s", url, err)
		}

		//  fmt.Println(string(bytes))
		if err = xml.Unmarshal(bytes, &cwes); err != nil {
			return cwes, fmt.Errorf(
				"Failed to unmarshal. url: %s, err: %s", url, err)
		}
	}
	return
}
