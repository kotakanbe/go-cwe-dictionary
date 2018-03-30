package golang

import (
	"bytes"
	"text/template"

	"github.com/kotakanbe/go-cwe-dictionary/models"
)

// GenerateJVN  go const definition
func GenerateJVN(cwes []models.Cwe) (string, error) {
	return Generate(cwes, tmplJVN)
}

// GenerateNVD go const definition
func GenerateNVD(cwes []models.Cwe) (string, error) {
	return Generate(cwes, tmplNVD)
}

// Generate go const definition
func Generate(cwes []models.Cwe, tmplstr string) (string, error) {
	tmpl, err := template.New("detail").Parse(tmplstr)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(nil) // create empty buffer
	if err := tmpl.Execute(buf, cwes); err != nil {
		return "", err
	}
	return string(buf.Bytes()), nil
}

const tmplNVD = `
package cwe

// Cwe has CWE information
type Cwe struct {
	CweID               string
	Name                string
	Description         string
	ExtendedDescription string
	Lang                string ` + "`" + `json:"-"` + "`" + `
}

// CweDictEn is the Cwe dictionary
var CweDictEn = map[string]Cwe {
{{range $cwe := . -}}
    "{{$cwe.CweID}}" : {
		CweID                 : "{{$cwe.CweID}}",
		Name                  : "{{$cwe.Name}}",
		Description           : "{{$cwe.Description}}",
		ExtendedDescription   : "{{$cwe.ExtendedDescription}}",
		Lang                  : "en",
	},
{{end}}
}
`

const tmplJVN = `
package cwe

// CweDictJa is the Cwe dictionary
var CweDictJa = map[string]Cwe {
{{range $cwe := . -}}
    "{{$cwe.CweID}}" : {
		CweID                 : "{{$cwe.CweID}}",
		Name                  : "{{$cwe.Name}}",
		Description           : "{{$cwe.Description}}",
		ExtendedDescription   : "{{$cwe.ExtendedDescription}}",
		Lang                  : "ja",
	},
{{end}}
}
`
