package controller

import (
	"context"
	"path"
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

func ObjectKey(obj Object) string {
	gvk := obj.GetObjectKind().GroupVersionKind()
	return path.Join(gvk.Group, gvk.Version, gvk.Kind, obj.GetNamespace(), obj.GetName())
}
