package resource

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"

	"github.com/samber/lo"
	"gopkg.in/inf.v0"
	corev1 "k8s.io/api/core/v1"

	"github.com/castai/sec-agent/controller"
)

type node struct {
	name              string
	allocatableMemory *inf.Dec
	allocatableCPU    *inf.Dec
}

type Subscriber struct {
	nodes map[string]*node
	mu    sync.RWMutex
}

func NewSubscriber() *Subscriber {
	return &Subscriber{
		nodes: make(map[string]*node),
		mu:    sync.RWMutex{},
	}
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	n, ok := obj.(*corev1.Node)
	if !ok {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.nodes[n.GetName()] = &node{
		name:              n.GetName(),
		allocatableMemory: n.Status.Allocatable.Memory().AsDec(),
		allocatableCPU:    n.Status.Allocatable.Cpu().AsDec(),
	}
}

func (s *Subscriber) OnUpdate(obj controller.Object) {
	s.OnAdd(obj)
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.nodes, obj.GetName())
}

func (s *Subscriber) Run(ctx context.Context) error {
	<-ctx.Done()

	return ctx.Err()
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return []reflect.Type{reflect.TypeOf(&corev1.Node{})}
}

func (s *Subscriber) FindBestNode(nodeNames []string, requiredMemory *inf.Dec) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(nodeNames) == 0 {
		return "", errors.New("no nodeNames provided")
	}

	var candidates []*node
	for nodeName, n := range s.nodes {
		if !lo.Contains(nodeNames, nodeName) {
			continue
		}

		candidates = append(candidates, n)
	}

	if len(candidates) == 0 {
		return "", errors.New("no candidates")
	}

	filteredCandidates := lo.Filter(candidates, func(n *node, _ int) bool {
		return n.allocatableMemory.Cmp(requiredMemory) > -1
	})

	if len(filteredCandidates) == 0 {
		return "", errors.New("no allocatable resources")
	}

	sort.Slice(filteredCandidates, func(i, j int) bool {
		return filteredCandidates[i].allocatableCPU.Cmp(filteredCandidates[j].allocatableCPU) > 0
	})

	return filteredCandidates[0].name, nil
}
