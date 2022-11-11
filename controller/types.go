package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"

	json "github.com/json-iterator/go"
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
	return string(obj.GetUID())
}

func ObjectHash(obj Object) (string, error) {
	h := sha256.New()
	// Use std compatible json config since we need sorted map keys.
	b, err := json.ConfigCompatibleWithStandardLibrary.Marshal(obj)
	if err != nil {
		return "", err
	}
	h.Write(b)
	hash := hex.EncodeToString(h.Sum(nil))
	return hash, nil
}
