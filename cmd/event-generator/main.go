package main

import (
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/castai/logging"

	"github.com/castai/kvisor/cmd/event-generator/app"
)

var (
	Version       = "local"
	logLevel      = pflag.String("log-level", logrus.DebugLevel.String(), "log level")
	mode          = pflag.String("mode", "controller", "Run as controller or single event generator")
	thiefDelay    = pflag.Duration("thief-delay", 90*time.Second, "")
	thiefInterval = pflag.Duration("thief-interval", 30*time.Second, "")
)

func main() {
	pflag.Parse()

	log := logging.New(logging.NewTextHandler(logging.TextHandlerConfig{
		Level: logging.MustParseLevel(*logLevel),
	}))

	genapp, err := app.New(&app.Config{
		Version:       Version,
		Log:           log,
		Kubeconfig:    "",
		ThiefDelay:    *thiefDelay,
		ThiefInterval: *thiefInterval,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
	if err := genapp.Run(*mode); err != nil {
		log.Fatal(err.Error())
	}
}
