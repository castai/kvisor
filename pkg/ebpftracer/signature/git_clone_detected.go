package signature

import (
	"net/url"
	"strings"

	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
)

var _ Signature = (*GitCloneDetected)(nil)

type GitCloneDetected struct {
	log *logging.Logger
}

func NewGitCloneDetectedSignature(log *logging.Logger) *GitCloneDetected {
	return &GitCloneDetected{
		log: log,
	}
}

func (*GitCloneDetected) GetMetadata() SignatureMetadata {
	return SignatureMetadata{
		ID:      v1.SignatureEventID_SIGNATURE_GIT_CLONE_DETECTED,
		Name:    "git_clone_detected",
		Version: "0.0.1",
		TargetEvents: []events.ID{
			events.SchedProcessExec,
		},
	}
}

func (s *GitCloneDetected) OnEvent(event *types.Event) *v1.SignatureFinding {
	exec, ok := event.Args.(types.SchedProcessExecArgs)
	if !ok {
		return nil
	}

	// For now we are only interested in using git directly.
	if exec.Argv[0] != "git" {
		return nil
	}

	repo, cloneFound := findCloneAndRepository(exec.Argv[1:])
	if !cloneFound {
		return nil
	}

	finding := &v1.GitCloneDetectedFinding{
		FullRepo: repo,
	}

	if repo != "" {
		t, server, path, found := parseRepo(repo)
		if found {
			finding.Type = t
			finding.Server = server
			finding.RepoPath = path
		}
	}

	return &v1.SignatureFinding{
		Data: &v1.SignatureFinding_GitCloneDetected{
			GitCloneDetected: finding,
		},
	}
}

func parseRepo(repo string) (v1.GitCloneRemoteType, string, string, bool) {
	u, err := url.Parse(repo)
	if err == nil {
		t := schemeToType(u.Scheme)
		if t == v1.GitCloneRemoteType_GIT_REMOTE_LOCAL {
			// For local repos ala `file:///path` we do not want to trim `/`. It would remove the leading
			// slash for absolute paths.
			return t, "", u.Path, true
		}
		if t != v1.GitCloneRemoteType_GIT_REMOTE_UNKNOWN {
			return t, strings.Trim(u.Host, "/"), strings.Trim(u.Path, "/"), true
		} else {
			// If we ever encounter an unknown custom transport, we will still try to return server
			// and path. That is why we search for the `://` substring. It could yield false positives,
			// but should be good enough.
			if strings.Contains(repo, "://") {
				return t, strings.Trim(u.Host, "/"), strings.Trim(u.Path, "/"), true
			}
		}
	}

	colonIdx := strings.Index(repo, ":")
	firstSlashIdx := strings.Index(repo, "/")

	// Short syntax requires that there is no `/` before the first `:`.
	if colonIdx != -1 && ((firstSlashIdx != -1 && colonIdx < firstSlashIdx) || firstSlashIdx == -1) {
		atIdx := strings.Index(repo, "@")
		if atIdx > -1 {
			repo = repo[atIdx+1:]
			colonIdx -= atIdx
		}

		return v1.GitCloneRemoteType_GIT_REMOTE_SSH, repo[:colonIdx-1], repo[colonIdx:], true
	}

	return v1.GitCloneRemoteType_GIT_REMOTE_LOCAL, "", repo, false
}

func schemeToType(scheme string) v1.GitCloneRemoteType {
	switch scheme {
	case "ssh":
		return v1.GitCloneRemoteType_GIT_REMOTE_SSH
	case "git":
		return v1.GitCloneRemoteType_GIT_REMOTE_GIT
	case "http":
		return v1.GitCloneRemoteType_GIT_REMOTE_HTTP
	case "https":
		return v1.GitCloneRemoteType_GIT_REMOTE_HTTPS
	case "ftp":
		return v1.GitCloneRemoteType_GIT_REMOTE_FTP
	case "ftps":
		return v1.GitCloneRemoteType_GIT_REMOTE_FTPS
	case "file":
		return v1.GitCloneRemoteType_GIT_REMOTE_LOCAL
	}
	return v1.GitCloneRemoteType_GIT_REMOTE_UNKNOWN
}

// The git flags should be fairely stable. Docs for the flags can be found
// in the official git docs https://git-scm.com/docs/git-clone
var gitFlags map[string]bool = map[string]bool{
	"--template":               true,
	"-l":                       false,
	"-s":                       false,
	"--no-hardlinks":           false,
	"-q":                       false,
	"-n":                       false,
	"--bare":                   false,
	"--mirror":                 false,
	"-o":                       true,
	"-b":                       true,
	"-u":                       true,
	"--reference":              true,
	"--dissociate":             false,
	"--separate-git-dir":       true,
	"--depth":                  true,
	"--single-branch":          false,
	"--no-single-branch":       false,
	"--no-tags":                false,
	"--recurse-submodules":     true,
	"--no-shallow-submodules":  false,
	"--shallow-submodules":     false,
	"--no-remote-submodules":   false,
	"--remote-submodules":      false,
	"--jobs":                   true,
	"--sparse":                 false,
	"--no-reject-shallow":      false,
	"--reject-shallow":         false,
	"--filter":                 true,
	"--also-filter-submodules": false,
}

func findCloneAndRepository(args []string) (string, bool) {
	cloneFound := false
	foundDashes := false
	lastArgumentExpectsValue := false

	for _, v := range args {
		if !cloneFound && v == "clone" {
			cloneFound = true
			continue
		}

		if cloneFound {
			if v == "--" {
				foundDashes = true
				continue
			}

			// The first argument after double dashes is always the repo.
			if foundDashes {
				return v, true
			}

			if lastArgumentExpectsValue {
				lastArgumentExpectsValue = false
				continue
			}

			if v[0] == '-' {
				if strings.Contains(v, "=") {
					lastArgumentExpectsValue = false
					continue
				}

				lastArgumentExpectsValue = gitFlags[v]
				continue
			}

			if lastArgumentExpectsValue {
				lastArgumentExpectsValue = false
				continue
			} else {
				return v, true
			}
		}
	}

	return "", cloneFound
}
