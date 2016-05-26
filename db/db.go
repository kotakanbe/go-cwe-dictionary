package db

import (
	"fmt"

	"github.com/cheggaaa/pb"
	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	c "github.com/kotakanbe/go-cwe-dictionary/config"
	log "github.com/kotakanbe/go-cwe-dictionary/log"
	"github.com/kotakanbe/go-cwe-dictionary/models"
)

var db *gorm.DB

// Init open DB connection
func Init(conf c.Config) error {
	if err := OpenDB(conf); err != nil {
		return err
	}
	if err := MigrateDB(); err != nil {
		return err
	}
	return nil
}

// OpenDB opens Database
func OpenDB(conf c.Config) (err error) {
	db, err = gorm.Open("sqlite3", conf.DBPath)
	if err != nil {
		err = fmt.Errorf("Failed to open DB. datafile: %s, err: %s", conf.DBPath, err)
		return

	}
	db.LogMode(conf.DebugSQL)
	return
}

// MigrateDB migrates Database
func MigrateDB() error {
	log.Info("Migrating Tables")
	if err := db.AutoMigrate(
		&models.Cwe{},
	).Error; err != nil {
		return fmt.Errorf("Failed to migrate. err: %s", err)
	}

	errMsg := "Failed to create index. err: %s"
	if err := db.Model(&models.Cwe{}).
		AddUniqueIndex("idx_cwe_id", "cwe_id").Error; err != nil {
		return fmt.Errorf(errMsg, err)
	}
	return nil
}

func chunkSlice(l []models.Cwe, n int) chan []models.Cwe {
	ch := make(chan []models.Cwe)
	go func() {
		for i := 0; i < len(l); i += n {
			fromIdx := i
			toIdx := i + n
			if toIdx > len(l) {
				toIdx = len(l)
			}
			ch <- l[fromIdx:toIdx]
		}
		close(ch)
	}()
	return ch
}

// InsertCwes inserts Cwe Information into DB
func InsertCwes(cwes []models.Cwe, conf c.Config) error {
	insertedCwes := []string{}
	bar := pb.StartNew(len(cwes))

	for chunked := range chunkSlice(cwes, 100) {
		tx := db.Begin()
		for _, c := range chunked {
			bar.Increment()

			// select old record.
			if err := tx.Create(&c).Error; err != nil {
				tx.Rollback()
				return fmt.Errorf("Failed to insert. cve: %s, err: %s",
					pp.Sprintf("%v", c),
					err,
				)
			}
			insertedCwes = append(insertedCwes, c.CweID)
		}
		tx.Commit()
	}
	bar.Finish()

	log.Infof("Inserted %d CWEs", len(insertedCwes))
	//  log.Debugf("%v", refreshedNvds)
	return nil
}

// CountCwe count nvd table
func CountCwe() (int, error) {
	var count int
	if err := db.Model(&models.Cwe{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// Get select CWE information from DB.
func Get(cweID string) models.Cwe {
	c := models.Cwe{}
	db.Where(&models.Cwe{CweID: cweID}).First(&c)
	if c.ID == 0 {
		return models.Cwe{}
	}
	return c
}
