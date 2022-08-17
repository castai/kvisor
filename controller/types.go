package controller

import (
	"fmt"
	"reflect"

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
	fmt.Println(i.Obj.GetObjectKind().GroupVersionKind())
	return fmt.Sprintf("%s::%s/%s", reflect.TypeOf(i.Obj).String(), i.Obj.GetNamespace(), i.Obj.GetName())
}
