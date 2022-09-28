package castai

import (
	"time"

	"github.com/sirupsen/logrus"
)

type LogEvent struct {
	Level   string        `json:"level"`
	Time    time.Time     `json:"time"`
	Message string        `json:"message"`
	Fields  logrus.Fields `json:"fields"`
}
