package allow

import (
	"gopkg.in/inf.v0"
	"k8s.io/apimachinery/pkg/types"
)

type pod struct {
	id            types.UID
	requestCPU    *inf.Dec
	requestMemory *inf.Dec
}

type node struct {
	name           string
	allocatableMem *inf.Dec
	allocatableCPU *inf.Dec
	pods           map[types.UID]*pod
}

func (n *node) availableMemory() *inf.Dec {
	var result inf.Dec
	result.Add(&result, n.allocatableMem)

	for _, p := range n.pods {
		result.Sub(&result, p.requestMemory)
	}

	return &result
}

func (n *node) availableCPU() *inf.Dec {
	var result inf.Dec
	result.Add(&result, n.allocatableCPU)

	for _, p := range n.pods {
		result.Sub(&result, p.requestCPU)
	}

	return &result
}
