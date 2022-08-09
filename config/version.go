package config

import "fmt"

type SecurityAgentVersion struct {
	GitCommit, GitRef, Version string
}

func (a *SecurityAgentVersion) String() string {
	return fmt.Sprintf("GitCommit=%q GitRef=%q Version=%q", a.GitCommit, a.GitRef, a.Version)
}
