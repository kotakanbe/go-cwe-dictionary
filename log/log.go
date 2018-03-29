package log

import (
	"fmt"
	"os"

	formatter "github.com/kotakanbe/logrus-prefixed-formatter"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
)

var logger *logrus.Entry

// package initializer
func init() {
	log := logrus.New()
	log.Formatter = &formatter.TextFormatter{}
	log.Out = os.Stderr
	log.Level = logrus.InfoLevel

	logDir := "/var/log/vuls"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.Mkdir(logDir, 0666); err != nil {
			logrus.Errorf("Failed to create log directory: %s", err)
		}
	}

	if _, err := os.Stat(logDir); err == nil {
		path := fmt.Sprintf("%s/cve-dictitnary.log", logDir)
		log.Hooks.Add(lfshook.NewHook(lfshook.PathMap{
			logrus.DebugLevel: path,
			logrus.InfoLevel:  path,
			logrus.WarnLevel:  path,
			logrus.ErrorLevel: path,
			logrus.FatalLevel: path,
			logrus.PanicLevel: path,
		}, nil))
	}

	fields := logrus.Fields{"prefix": ""}
	logger = log.WithFields(fields)
}

// SetDebug set debug level
func SetDebug() {
	logger.Level = logrus.DebugLevel
}

// Debugf is wrapper function
func Debugf(format string, args ...interface{}) {
	logger.Debugf(format, args...)
}

// Infof is wrapper function
func Infof(format string, args ...interface{}) {
	logger.Infof(format, args...)
}

// Printf is wrapper function
func Printf(format string, args ...interface{}) {
	logger.Printf(format, args...)
}

// Warnf is wrapper function
func Warnf(format string, args ...interface{}) {
	logger.Warnf(format, args...)
}

// Errorf is wrapper function
func Errorf(format string, args ...interface{}) {
	logger.Errorf(format, args...)
}

// Fatalf is wrapper function
func Fatalf(format string, args ...interface{}) {
	logger.Fatalf(format, args...)
}

// Panicf is wrapper function
func Panicf(format string, args ...interface{}) {
	logger.Panicf(format, args...)
}

// Debug is wrapper function
func Debug(args ...interface{}) {
	logger.Debug(args...)
}

// Info is wrapper function
func Info(args ...interface{}) {
	logger.Info(args...)
}

// Print is wrapper function
func Print(args ...interface{}) {
	logger.Print(args...)
}

// Warn is wrapper function
func Warn(args ...interface{}) {
	logger.Warn(args...)
}

// Error is wrapper function
func Error(args ...interface{}) {
	logger.Error(args...)
}

// Fatal is wrapper function
func Fatal(args ...interface{}) {
	logger.Fatal(args...)
}

// Panic is wrapper function
func Panic(args ...interface{}) {
	logger.Panic(args...)
}
