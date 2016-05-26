package config

import (
	valid "github.com/asaskevich/govalidator"
	log "github.com/kotakanbe/go-cwe-dictionary/log"
)

// Conf has global configuration
var Conf Config

// Config has configuration
type Config struct {
	Debug    bool
	DebugSQL bool

	DBPath string

	Bind string `valid:"ipv4"`
	Port string `valid:"port"`

	HTTPProxy string
}

// Validate validates configuration
func (c *Config) Validate() bool {
	if ok, _ := valid.IsFilePath(c.DBPath); !ok {
		log.Errorf("--dbpath : %s is not valid *Absolute* file path", c.DBPath)
		return false
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
		log.Errorf("error: " + err.Error())
		return false
	}
	return true
}
