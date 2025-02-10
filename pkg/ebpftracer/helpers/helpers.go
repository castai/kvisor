package helpers

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func SetVariable(spec *ebpf.CollectionSpec, variable string, value any) error {
	v, found := spec.Variables[variable]
	if !found {
		return fmt.Errorf("variable `%s` not found", variable)
	}

  if err:= v.Set(value); err != nil {
    return fmt.Errorf("error while setting variable `%s`: %w", variable, err)
  }

  return nil
}
