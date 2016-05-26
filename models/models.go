package models

import (
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/kotakanbe/go-cwe-dictionary/cwe"
)

// Cwe has CPE information
type Cwe struct {
	gorm.Model

	CweID       string
	Type        string
	Name        string
	Summary     string
	Description string
}

// ConvertToModel convert Cwe Struct to model
func ConvertToModel(cwes cwe.WeaknessCatalog) (cweModels []Cwe) {
	for _, item := range cwes.Views {
		cweModels = append(cweModels, Cwe{
			Type:    "view",
			CweID:   item.ID,
			Name:    item.Name,
			Summary: strings.Join(item.Text, "\n"),
		})
	}
	for _, item := range cwes.Categories {
		cweModels = append(cweModels, Cwe{
			Type:    "catetory",
			CweID:   item.ID,
			Name:    item.Name,
			Summary: item.DescriptionSummary,
		})
	}
	for _, item := range cwes.Weaknesses {
		cweModels = append(cweModels, Cwe{
			Type:        "weakness",
			CweID:       item.ID,
			Name:        item.Name,
			Summary:     item.DescriptionSummary,
			Description: item.ExtendedDescription,
		})
	}
	for _, item := range cwes.CompoundElements {
		cweModels = append(cweModels, Cwe{
			Type:        "compoundElement",
			CweID:       item.ID,
			Name:        item.Name,
			Summary:     item.DescriptionSummary,
			Description: item.ExtendedDescription,
		})
	}
	return
}
