package controller

import (
	"context"
	"reflect"

	"k8s.io/client-go/tools/cache"
)

type ObjectSubscriber interface {
	cache.ResourceEventHandler

	Run(ctx context.Context) error
	RequiredInformers() []reflect.Type
	Supports(typ reflect.Type) bool
}
