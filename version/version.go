package version

import (
	"fmt"
	"regexp"
	"strconv"

	"k8s.io/client-go/kubernetes"
)

func Get(clientset kubernetes.Interface) (Version, error) {
	cs, ok := clientset.(*kubernetes.Clientset)
	if !ok {
		return Version{}, fmt.Errorf("expected clientset to be of type *kubernetes.Clientset but was %T", clientset)
	}

	sv, err := cs.ServerVersion()
	if err != nil {
		return Version{}, fmt.Errorf("getting server version: %w", err)
	}

	m, err := strconv.Atoi(regexp.MustCompile(`^(\d+)`).FindString(sv.Minor))
	if err != nil {
		return Version{}, fmt.Errorf("parsing minor version: %w", err)
	}

	return Version{
		Full:     sv.Major + "." + sv.Minor,
		MinorInt: m,
	}, nil
}

type Version struct {
	Full     string
	MinorInt int
}
