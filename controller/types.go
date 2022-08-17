package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type event string

const (
	eventAdd    event = "add"
	eventDelete event = "delete"
	eventUpdate event = "update"
)

type object interface {
	runtime.Object
	metav1.Object
}

type item struct {
	obj   object
	event event
}
