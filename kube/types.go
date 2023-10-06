package kube

import (
	"context"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ResourceEventHandler interface {
	OnAdd(obj Object)
	OnUpdate(obj Object)
	OnDelete(obj Object)
}

type ObjectSubscriber interface {
	ResourceEventHandler
	Run(ctx context.Context) error
	RequiredInformers() []reflect.Type
}

type Event string

const (
	EventAdd    Event = "add"
	EventDelete Event = "delete"
	EventUpdate Event = "update"
)

type Object interface {
	runtime.Object
	metav1.Object
}
