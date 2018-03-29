package models

import (
	"github.com/jinzhu/gorm"
	"github.com/kotakanbe/go-cwe-dictionary/cwe"
)

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
