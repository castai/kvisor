package signature

import (
	"testing"

	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestFindCloneAndRepository(t *testing.T) {
	type testCase struct {
		name               string
		args               []string
		expectedRepo       string
		expectedCloneFound bool
	}

	testCases := []testCase{
		{
			name:               "empty args",
			args:               []string{},
			expectedRepo:       "",
			expectedCloneFound: false,
		},
		{
			name:               "only clone command",
			args:               []string{"clone"},
			expectedRepo:       "",
			expectedCloneFound: true,
		},
		{
			name:               "flags before clone and repo",
			args:               []string{"--bare", "clone", "https://repo.com"},
			expectedRepo:       "https://repo.com",
			expectedCloneFound: true,
		},
		{
			name:               "clone with flags that expect value and no repo and flag before clone",
			args:               []string{"--bare", "clone", "--filter", "https://repo.com"},
			expectedRepo:       "",
			expectedCloneFound: true,
		},
		{
			name:               "clone with flags that expect value and repo",
			args:               []string{"--bare", "clone", "--filter", "repo", "https://repo.com"},
			expectedRepo:       "https://repo.com",
			expectedCloneFound: true,
		},
		{
			name:               "clone with flag that requries value and no repo",
			args:               []string{"clone", "--template", "https://test"},
			expectedRepo:       "",
			expectedCloneFound: true,
		},
		{
			name:               "clone with double dashes",
			args:               []string{"--bare", "clone", "--filter", "repo", "--", "https://repo.com"},
			expectedRepo:       "https://repo.com",
			expectedCloneFound: true,
		},
		{
			name:               "clone with double dashes and dir",
			args:               []string{"--bare", "clone", "--filter", "repo", "--", "https://repo.com", "out"},
			expectedRepo:       "https://repo.com",
			expectedCloneFound: true,
		},
		{
			name:               "clone with repo and dir",
			args:               []string{"--bare", "clone", "--filter", "repo", "https://repo.com", "out"},
			expectedRepo:       "https://repo.com",
			expectedCloneFound: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			actualFoundRepo, actualCloneFound := findCloneAndRepository(test.args)

			if test.expectedCloneFound {
				r.True(actualCloneFound)
				r.Equal(test.expectedRepo, actualFoundRepo)
			} else {
				r.False(actualCloneFound)
			}
		})
	}

}

func TestParseRepo(t *testing.T) {
	type testCase struct {
		name             string
		input            string
		expectedType     v1.GitCloneRemoteType
		expectedServer   string
		expectedRepoPath string
		extectedFound    bool
	}

	testCases := []testCase{
		{
			name:             "full ssh with proto",
			input:            "ssh://hello@github.com:1234/my-org/my-fancy-repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_SSH,
			expectedServer:   "github.com:1234",
			expectedRepoPath: "my-org/my-fancy-repo",
			extectedFound:    true,
		},
		{
			name:             "full ssh with proto without port",
			input:            "ssh://hello@github.com/my-org/my-fancy-repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_SSH,
			expectedServer:   "github.com",
			expectedRepoPath: "my-org/my-fancy-repo",
			extectedFound:    true,
		},
		{
			name:             "ssh short syntax",
			input:            "test@github.com:my-org/my-fancy-repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_SSH,
			expectedServer:   "github.com",
			expectedRepoPath: "my-org/my-fancy-repo",
			extectedFound:    true,
		},
		{
			name:             "git protocol",
			input:            "git://my-host.local/my-org/my-fancy-repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_GIT,
			expectedServer:   "my-host.local",
			expectedRepoPath: "my-org/my-fancy-repo",
			extectedFound:    true,
		},
		{
			name:             "http protocol",
			input:            "http://my-host.local/my-org/my-fancy-repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_HTTP,
			expectedServer:   "my-host.local",
			expectedRepoPath: "my-org/my-fancy-repo",
			extectedFound:    true,
		},
		{
			name:             "https protocol",
			input:            "https://my-host.local/my-org/my-fancy-repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_HTTPS,
			expectedServer:   "my-host.local",
			expectedRepoPath: "my-org/my-fancy-repo",
			extectedFound:    true,
		},
		{
			name:             "ftp protocol",
			input:            "ftp://my-host.local/my-org/my-fancy-repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_FTP,
			expectedServer:   "my-host.local",
			expectedRepoPath: "my-org/my-fancy-repo",
			extectedFound:    true,
		},
		{
			name:             "ftps protocol",
			input:            "ftps://my-host.local/my-org/my-fancy-repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_FTPS,
			expectedServer:   "my-host.local",
			expectedRepoPath: "my-org/my-fancy-repo",
			extectedFound:    true,
		},
		{
			name:             "local repo",
			input:            "/path/to/repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_LOCAL,
			expectedServer:   "",
			expectedRepoPath: "/path/to/repo",
			extectedFound:    true,
		},
		{
			name:             "local repo file prefix",
			input:            "file:///path/to/repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_LOCAL,
			expectedServer:   "",
			expectedRepoPath: "/path/to/repo",
			extectedFound:    true,
		},
		{
			name:             "local repo with colon in name",
			input:            "/path/to:repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_LOCAL,
			expectedServer:   "",
			expectedRepoPath: "/path/to:repo",
			extectedFound:    true,
		},
		{
			name:             "relative local repo with colon in name",
			input:            "./path:to:repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_LOCAL,
			expectedServer:   "",
			expectedRepoPath: "./path:to:repo",
			extectedFound:    true,
		},
		{
			name:             "unknown protocol",
			input:            "magic://my-host.local/my-org/my-fancy-repo",
			expectedType:     v1.GitCloneRemoteType_GIT_REMOTE_UNKNOWN,
			expectedServer:   "my-host.local",
			expectedRepoPath: "my-org/my-fancy-repo",
			extectedFound:    true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			repoType, server, path, found := parseRepo(test.input)

			if !test.extectedFound {
				r.False(found)
			} else {
				r.Equal(test.expectedType.String(), repoType.String())
				r.Equal(test.expectedServer, server)
				r.Equal(test.expectedRepoPath, path)
			}
		})
	}

}

func TestGitCloneDetectedSignature(t *testing.T) {
	type eventWithFinding struct {
		event           types.Event
		expectedFinding *v1.SignatureFinding
	}

	type testCase struct {
		title  string
		events []eventWithFinding
	}

	testCases := []testCase{
		{
			title: "should report git clone",
			events: []eventWithFinding{
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.SchedProcessExec,
							Ts:       11,
							CgroupID: 10,
							Pid:      99,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.SchedProcessExecArgs{
							Filename: "git",
							Filepath: "/usr/bin",
							Argv:     []string{"git", "clone", "git@github.com:castai/kvisor.git"},
						},
					},
					expectedFinding: &v1.SignatureFinding{
						Data: &v1.SignatureFinding_GitCloneDetected{
							GitCloneDetected: &v1.GitCloneDetectedFinding{
								Type:     v1.GitCloneRemoteType_GIT_REMOTE_SSH,
								FullRepo: "git@github.com:castai/kvisor.git",
								Server:   "github.com",
								RepoPath: "castai/kvisor.git",
							},
						},
					},
				},
			},
		},
		{
			title: "should report nothing for non git clone",
			events: []eventWithFinding{
				{
					event: types.Event{
						Context: &types.EventContext{
							EventID:  events.SchedProcessExec,
							Ts:       11,
							CgroupID: 10,
							Pid:      99,
						},
						Container: &containers.Container{
							ID:       "123",
							Name:     "name-123",
							CgroupID: 10,
						},
						Args: types.SchedProcessExecArgs{
							Filename: "git",
							Filepath: "/usr/bin",
							Argv:     []string{"git", "not-clone", "git@github.com:castai/kvisor.git"},
						},
					},
				},
			},
		},
	}

	log := logging.New(&logging.Config{})

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			signature := NewGitCloneDetectedSignature(log, GitCloneSignatureConfig{
				RedactPasswords: true,
			})

			for i, e := range test.events {
				result := signature.OnEvent(&e.event)

				if e.expectedFinding == nil {
					r.Nil(result)
					continue
				}
				r.Equal(e.expectedFinding, result, "match finding for event nr. %d: %d", i, e.event.Context.EventID)
			}
		})
	}
}

func Test_redactPasswords(t *testing.T) {
	tests := []struct {
		name string
		repo string
		want string
	}{
		{
			name: "url with username",
			repo: "https://user@repo.com",
			want: "https://user@repo.com",
		},
		{
			name: "url with username and password",
			repo: "https://user:password@repo.com",
			want: "https://user:redacted@repo.com",
		},
		{
			name: "clone local repo with relative path",
			repo: "./repo",
			want: "./repo",
		},
		{
			name: "clone local repo with absolute path",
			repo: "/repo",
			want: "/repo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := require.New(t)

			got := redactPasswords(tt.repo)

			r.Equal(tt.want, got)
		})
	}
}
