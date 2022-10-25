package alloc

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"

	"gopkg.in/inf.v0"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/castai/sec-agent/controller"
)

var (
	ErrNoCandidates = errors.New("no candidates")
)

type Subscriber struct {
	tree map[string]*node
	mu   sync.RWMutex
}

func NewSubscriber() *Subscriber {
	return &Subscriber{
		tree: make(map[string]*node),
		mu:   sync.RWMutex{},
	}
}

func (s *Subscriber) OnAdd(obj controller.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch v := obj.(type) {
	case *corev1.Node:
		if _, ok := s.tree[v.GetName()]; !ok {
			s.tree[v.GetName()] = &node{
				name:           v.GetName(),
				allocatableMem: &inf.Dec{},
				allocatableCPU: &inf.Dec{},
				pods:           make(map[types.UID]*pod),
			}
		}

		s.tree[v.GetName()].allocatableMem = v.Status.Allocatable.Memory().AsDec()
		s.tree[v.GetName()].allocatableCPU = v.Status.Allocatable.Cpu().AsDec()
	case *corev1.Pod:
		if _, ok := s.tree[v.Spec.NodeName]; !ok {
			s.tree[v.Spec.NodeName] = &node{
				name:           v.Spec.NodeName,
				allocatableMem: &inf.Dec{},
				allocatableCPU: &inf.Dec{},
				pods:           make(map[types.UID]*pod),
			}
		}

		if _, ok := s.tree[v.Spec.NodeName].pods[v.GetUID()]; !ok {
			s.tree[v.Spec.NodeName].pods[v.GetUID()] = &pod{
				id:            v.GetUID(),
				requestCPU:    &inf.Dec{},
				requestMemory: &inf.Dec{},
			}
		}

		s.tree[v.Spec.NodeName].pods[v.GetUID()].requestMemory = sumPodRequestMemory(&v.Spec)
		s.tree[v.Spec.NodeName].pods[v.GetUID()].requestCPU = sumPodRequestCPU(&v.Spec)
	}
}

func (s *Subscriber) OnUpdate(obj controller.Object) {
	s.OnAdd(obj)
}

func (s *Subscriber) OnDelete(obj controller.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch v := obj.(type) {
	case *corev1.Node:
		delete(s.tree, v.GetName())
	case *corev1.Pod:
		if _, ok := s.tree[v.Spec.NodeName]; ok {
			delete(s.tree[v.Spec.NodeName].pods, obj.GetUID())
		}
	}
}

func (s *Subscriber) Run(ctx context.Context) error {
	<-ctx.Done()

	return ctx.Err()
}

func (s *Subscriber) RequiredInformers() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(&corev1.Node{}),
		reflect.TypeOf(&corev1.Pod{}),
	}
}

func (s *Subscriber) FindBestNode(nodeNames []string, requiredMemory *inf.Dec) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var candidates []*node
	for _, nodeName := range nodeNames {
		if _, ok := s.tree[nodeName]; !ok {
			continue
		}

		candidates = append(candidates, s.tree[nodeName])
	}

	var filteredCandidates []*node
	for _, n := range candidates {
		if n.availableMemory().Cmp(requiredMemory) < 0 {
			continue
		}

		filteredCandidates = append(filteredCandidates, n)
	}

	if len(filteredCandidates) == 0 {
		return "", ErrNoCandidates
	}

	sort.Slice(filteredCandidates, func(i, j int) bool {
		return filteredCandidates[i].availableCPU().Cmp(filteredCandidates[j].allocatableCPU) > 0
	})

	return filteredCandidates[0].name, nil
}

func sumPodRequestMemory(spec *corev1.PodSpec) *inf.Dec {
	var result inf.Dec
	for _, container := range spec.Containers {
		result = *result.Add(&result, container.Resources.Requests.Memory().AsDec())
	}

	return &result
}

func sumPodRequestCPU(spec *corev1.PodSpec) *inf.Dec {
	var result inf.Dec
	for _, container := range spec.Containers {
		result = *result.Add(&result, container.Resources.Requests.Cpu().AsDec())
	}

	return &result
}
