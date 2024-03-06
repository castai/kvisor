package main

import (
	"github.com/sirupsen/logrus"
)

//go:generate go build -ldflags "-w -s" -o ./server ./server.go
func main() {
	logrus.Debug("hello")
}
