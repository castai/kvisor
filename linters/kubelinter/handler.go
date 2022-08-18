package kubelinter

import (
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.stackrox.io/kube-linter/pkg/lintcontext"

	"github.com/castai/sec-agent/controller"
)

func NewHandler(log logrus.FieldLogger) *Handler {
	linter := New(rules)

	return &Handler{
		log:     log,
		objects: map[string]controller.Object{},
		linter:  linter,
	}
}

type Handler struct {
	log     logrus.FieldLogger
	objects map[string]controller.Object
	linter  *Linter
}

func (h *Handler) Handle(item *controller.Item) {
	key := item.ObjectKey()
	switch item.Event {
	case controller.EventAdd, controller.EventUpdate:
		h.objects[key] = item.Obj
	case controller.EventDelete:
		delete(h.objects, key)
	}

	// TODO: Queue items and handle periodically + wait for initial state to sync in informers.
	lintObjects := lo.Map(lo.Values(h.objects), func(t controller.Object, i int) lintcontext.Object {
		return lintcontext.Object{K8sObject: t}
	})

	checks, err := h.linter.Run(lintObjects)
	if err != nil {
		h.log.Errorf("lint failed: %v", err)
		return
	}
	h.log.Infof("lint finished, checks: %d", len(checks))
}
