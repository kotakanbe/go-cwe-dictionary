package golang

import (
	"bytes"
	"text/template"

	"github.com/kotakanbe/go-cwe-dictionary/models"
)

// Generate go const definition
func Generate(cwes []models.Cwe) (string, error) {
	tmpl, err := template.New("detail").Parse(tmpl)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(nil) // create empty buffer
	if err := tmpl.Execute(buf, cwes); err != nil {
		return "", err
	}
	return string(buf.Bytes()), nil
}

const tmpl = `
package cwe

// Cwe has CWE information
type Cwe struct {
	CweID                 string
	NameEn                string
	DescriptionEn         string
	ExtendedDescriptionEn string
}

// CweDict is the Cwe dictionary
var CweDict = map[string]Cwe {
{{range $cwe := . -}}
    "{{$cwe.CweID}}" : {
		CweID                 : "{{$cwe.CweID}}",
		NameEn                : "{{$cwe.Name}}",
		DescriptionEn         : "{{$cwe.Description}}",
		ExtendedDescriptionEn : "{{$cwe.ExtendedDescription}}",
	},
{{end}}
}
`
