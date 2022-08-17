package controller

import (
	"context"
	"reflect"

	"k8s.io/client-go/tools/cache"
)

type ObjectSubscriber interface {
	cache.ResourceEventHandler

	Supports(typ reflect.Type) bool
	Shutdown(ctx context.Context) error
}
