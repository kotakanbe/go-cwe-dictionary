package server

import (
	"fmt"
	"net/http"
	"os"

	c "github.com/kotakanbe/go-cwe-dictionary/config"
	db "github.com/kotakanbe/go-cwe-dictionary/db"
	log "github.com/kotakanbe/go-cwe-dictionary/log"
	"github.com/labstack/echo"
	"github.com/labstack/echo/engine/standard"
	"github.com/labstack/echo/middleware"
)

// Start starts CVE dictionary HTTP Server.
func Start() error {
	e := echo.New()
	e.SetDebug(c.Conf.Debug)

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// setup access logger
	logPath := "/var/log/vuls/access-cwe.log"
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		if _, err := os.Create(logPath); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	logconf := middleware.DefaultLoggerConfig
	logconf.Output = f
	e.Use(middleware.LoggerWithConfig(logconf))

	// Routes
	e.Get("/health", health())
	e.Get("/cwes/:id", getCwe())

	bindURL := fmt.Sprintf("%s:%s", c.Conf.Bind, c.Conf.Port)
	log.Infof("Listening on %s", bindURL)

	e.Run(standard.New(bindURL))
	return nil
}

// Handler
func health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "")
	}
}

// Handler
func getCwe() echo.HandlerFunc {
	return func(c echo.Context) error {
		cweid := c.Param("id")
		cwe := db.Get(cweid)
		return c.JSON(http.StatusOK, cwe)
	}
}
