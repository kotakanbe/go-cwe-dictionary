package models

import (
	"strings"

	"github.com/jinzhu/gorm"
	jvn "github.com/kotakanbe/go-cve-dictionary/fetcher/jvn/xml"
	"github.com/kotakanbe/go-cwe-dictionary/cwe"
)

// Cwes is a slice of Cwe
type Cwes []Cwe

// Uniq discinct Cwes by CWE-ID
func (cs Cwes) Uniq() (uniq []Cwe) {
	cweIDs := map[string]bool{}
	for _, c := range cs {
		if _, ok := cweIDs[c.CweID]; ok {
			continue
		}
		uniq = append(uniq, c)
		cweIDs[c.CweID] = true
	}
	return
}

// Cwe has CPE information
type Cwe struct {
	gorm.Model

	CweID               string
	Name                string
	Description         string
	ExtendedDescription string
}

// ConvertToModel convert Cwe Struct to model
func ConvertToModel(cwes cwe.WeaknessCatalog) (cweModels []Cwe) {
	for _, item := range cwes.Weaknesses {
		cweModels = append(cweModels, Cwe{
			CweID:               item.ID,
			Name:                item.Name,
			Description:         item.Description,
			ExtendedDescription: item.ExtendedDescription,
		})
	}
	return
}

// ConvertToModelJVN convert jvn.Item Struct to model
func ConvertToModelJVN(items []jvn.Item) (cweModels Cwes) {
	for _, item := range items {
		for _, ref := range item.References {
			if ref.ID == "CWE-Other" ||
				ref.ID == "CWE-DesignError" ||
				!strings.HasPrefix(ref.ID, "CWE-") {
				continue
			}
			cweModels = append(cweModels, Cwe{
				CweID: strings.TrimPrefix(ref.ID, "CWE-"),
				Name:  ref.Title,
			})
		}
	}
	return
}
