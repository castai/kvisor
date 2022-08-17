package controller

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ItemHandler interface {
	Handle(item *Item)
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

type Item struct {
	Obj   Object
	Event Event
}

func (i *Item) ObjectKey() string {
	kind := i.Obj.GetObjectKind().GroupVersionKind()
	return fmt.Sprintf(
		"%s/%s/%s/%s",
		kind.Version,
		kind.Kind,
		i.Obj.GetNamespace(),
		i.Obj.GetName(),
	)
}
