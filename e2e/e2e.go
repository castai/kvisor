package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
)

var (
	imageTag = pflag.String("image-tag", "", "Kvisord docker image tag")
	timeout  = pflag.Duration("timeout", 180*time.Second, "Test timeout")
	ns       = pflag.String("ns", "kvisord-e2e", "Namespace")
)

const (
	apiKey    = "x-test-api-key" //nolint:gosec
	clusterID = "x-test-cluster-id"
)

func main() {
	pflag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Printf("💥e2e failed: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if *imageTag == "" {
		return errors.New("image-tag flag is not set")
	}

	addr := fmt.Sprintf(":%d", 8443)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := grpc.NewServer()
	srv := &testCASTAIServer{}
	castaipb.RegisterRuntimeSecurityAgentAPIServer(s, srv)
	go func() {
		if err := s.Serve(lis); err != nil {
			fmt.Printf("serving grcp failed: %v\n", err)
		}
	}()

	out, err := installChart(*ns, *imageTag)
	if err != nil {
		return fmt.Errorf("installing chart: %w: %s", err, string(out))
	}
	fmt.Printf("installed chart:\n%s\n", out)

	fmt.Println("🙏waiting for events")
	if err := srv.assertEvents(ctx); err != nil {
		return fmt.Errorf("assert events: %w", err)
	}

	fmt.Println("🙏waiting for container stats")
	if err := srv.assertContainerStats(ctx); err != nil {
		return fmt.Errorf("assert container stats: %w", err)
	}

	fmt.Println("🙏waiting for kubernetes deltas")
	if err := srv.assertKubernetesDeltas(ctx); err != nil {
		return fmt.Errorf("assert k8s deltas: %w", err)
	}

	validateTimeout := 30 * time.Second
	fmt.Printf("🧐validating events (timeout %s)\n", validateTimeout)
	if err := srv.validateEvents(ctx, validateTimeout); err != nil {
		return fmt.Errorf("assert events: %w", err)
	}

	fmt.Println("🙏waiting for flogs")
	if err := srv.assertLogs(ctx); err != nil {
		return fmt.Errorf("assert logs: %w", err)
	}

	fmt.Println("🙏waiting for kube bench")
	if err := srv.assertKubeBenchReport(ctx); err != nil {
		return fmt.Errorf("assert kube bench: %w", err)
	}

	fmt.Println("🙏waiting for kube linter")
	if err := srv.assertKubeLinter(ctx); err != nil {
		return fmt.Errorf("assert kube linter: %w", err)
	}

	fmt.Println("🙏waiting for image metadata")
	if err := srv.assertImageMetadata(ctx); err != nil {
		return fmt.Errorf("assert image metadata: %w", err)
	}

	fmt.Println("👌e2e finished")

	return nil
}

func installChart(ns, imageTag string) ([]byte, error) {
	fmt.Printf("installing kvisord chart with image tag %q", imageTag)
	repo := "ghcr.io/castai/kvisor/kvisor"
	if imageTag == "local" {
		repo = "kvisord"
	}

	grpcAddr := fmt.Sprintf("%s:8443", os.Getenv("POD_IP"))
	//nolint:gosec
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf(
		`helm upgrade --install kvisord-e2e ./charts/kvisor \
  -n %s --create-namespace \
  --set image.repository=%s \
  --set image.tag=%s \
  --set agent.enabled=true \
  --set agent.extraArgs.log-level=debug \
  --set agent.extraArgs.container-stats-scrape-interval=5s \
  --set agent.extraArgs.castai-server-insecure=true \
  --set controller.extraArgs.castai-server-insecure=true \
  --set controller.extraArgs.log-level=debug \
  --set controller.extraArgs.kubernetes-delta-interval=5s \
  --set controller.extraArgs.kubernetes-delta-init-delay=5s \
  --set controller.extraArgs.image-scan-enabled=true \
  --set controller.extraArgs.image-scan-interval=5s \
  --set controller.extraArgs.image-scan-init-delay=5s \
  --set controller.extraArgs.kube-bench-enabled=true \
  --set controller.extraArgs.kube-bench-scan-interval=5s \
  --set controller.extraArgs.kube-bench-cloud-provider=gke \
  --set controller.extraArgs.kube-linter-enabled=true \
  --set controller.extraArgs.kube-linter-scan-interval=5s \
  --set controller.extraArgs.kube-linter-init-delay=5s \
  --set castai.grpcAddr=%s \
  --set castai.apiKey=%s \
  --set castai.clusterID=%s \
  --wait --timeout=5m`,
		ns,
		repo,
		imageTag,
		grpcAddr,
		apiKey,
		clusterID,
	))
	return cmd.CombinedOutput()
}

var _ castaipb.RuntimeSecurityAgentAPIServer = (*testCASTAIServer)(nil)

type testCASTAIServer struct {
	containerStats    []*castaipb.ContainerStatsBatch
	events            []*castaipb.Event
	logs              []*castaipb.LogEvent
	deltaUpdates      []*castaipb.KubernetesDeltaItem
	mu                sync.Mutex
	imageMetadatas    []*castaipb.ImageMetadata
	kubeBenchReports  []*castaipb.KubeBenchReport
	kubeLinterReports []*castaipb.KubeLinterReport
}

func (t *testCASTAIServer) KubeBenchReportIngest(ctx context.Context, report *castaipb.KubeBenchReport) (*castaipb.KubeBenchReportIngestResponse, error) {
	t.kubeBenchReports = append(t.kubeBenchReports, report)
	return &castaipb.KubeBenchReportIngestResponse{}, nil
}

func (t *testCASTAIServer) KubeLinterReportIngest(ctx context.Context, report *castaipb.KubeLinterReport) (*castaipb.KubeLinterReportIngestResponse, error) {
	t.kubeLinterReports = append(t.kubeLinterReports, report)
	return &castaipb.KubeLinterReportIngestResponse{}, nil
}

func (t *testCASTAIServer) ImageMetadataIngest(ctx context.Context, imageMetadata *castaipb.ImageMetadata) (*castaipb.ImageMetadataIngestResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.imageMetadatas = append(t.imageMetadatas, imageMetadata)

	return &castaipb.ImageMetadataIngestResponse{}, nil
}

func (t *testCASTAIServer) GetSyncState(ctx context.Context, request *castaipb.GetSyncStateRequest) (*castaipb.GetSyncStateResponse, error) {
	return &castaipb.GetSyncStateResponse{}, nil
}

func (t *testCASTAIServer) UpdateSyncState(ctx context.Context, request *castaipb.UpdateSyncStateRequest) (*castaipb.UpdateSyncStateResponse, error) {
	return &castaipb.UpdateSyncStateResponse{}, nil
}

func (t *testCASTAIServer) ContainerStatsWriteStream(server castaipb.RuntimeSecurityAgentAPI_ContainerStatsWriteStreamServer) error {
	for {
		msg, err := server.Recv()
		if err != nil {
			return err
		}
		fmt.Println("received container stats:", len(msg.Items))
		t.mu.Lock()
		t.containerStats = append(t.containerStats, msg)
		t.mu.Unlock()
	}
}

func (t *testCASTAIServer) GetConfiguration(ctx context.Context, request *castaipb.GetConfigurationRequest) (*castaipb.GetConfigurationResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("no metadata")
	}
	token := md["authorization"]
	if len(token) == 0 {
		return nil, errors.New("no authorization")
	}
	if token[0] != "Token "+apiKey {
		return nil, fmt.Errorf("invalid token %s", token[0])
	}

	cluster := md["x-cluster-id"]
	if len(cluster) == 0 {
		return nil, errors.New("no x-cluster-id")
	}
	if cluster[0] != clusterID {
		return nil, fmt.Errorf("invalid cluster ID %s", cluster[0])
	}
	return &castaipb.GetConfigurationResponse{}, nil
}

func (t *testCASTAIServer) EventsWriteStream(server castaipb.RuntimeSecurityAgentAPI_EventsWriteStreamServer) error {
	md, ok := metadata.FromIncomingContext(server.Context())
	if !ok {
		return errors.New("no metadata")
	}
	token := md["authorization"]
	if len(token) == 0 {
		return errors.New("no authorization")
	}
	if token[0] != "Token "+apiKey {
		return fmt.Errorf("invalid token %s", token[0])
	}
	cluster := md["x-cluster-id"]
	if len(cluster) == 0 {
		return errors.New("no x-cluster-id")
	}
	if cluster[0] != clusterID {
		return fmt.Errorf("invalid cluster ID %s", cluster[0])
	}

	for {
		event, err := server.Recv()
		if err != nil {
			return err
		}
		fmt.Println("received event:", event)
		t.mu.Lock()
		t.events = append(t.events, event)
		t.mu.Unlock()
	}
}

func (t *testCASTAIServer) LogsWriteStream(server castaipb.RuntimeSecurityAgentAPI_LogsWriteStreamServer) error {
	for {
		event, err := server.Recv()
		if err != nil {
			return err
		}
		fmt.Println("received log:", event)
		t.mu.Lock()
		t.logs = append(t.logs, event)
		t.mu.Unlock()
	}
}

func (t *testCASTAIServer) assertLogs(ctx context.Context) error {
	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for received logs")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			logs := t.logs
			t.mu.Unlock()
			if len(logs) > 0 {
				l1 := logs[0]
				if l1.Msg == "" {
					return errors.New("missing log msg")
				}

				for _, l := range logs {
					if strings.Contains(l.Msg, "panic") {
						return fmt.Errorf("received logs contains panic error: %s", l.Msg)
					}
				}

				return nil
			}
		}
	}
}

func (t *testCASTAIServer) validateEvents(ctx context.Context, timeout time.Duration) error {
	expectedTypes := map[castaipb.EventType]struct{}{
		castaipb.EventType_EVENT_EXEC:        {},
		castaipb.EventType_EVENT_DNS:         {},
		castaipb.EventType_EVENT_TCP_CONNECT: {},
		castaipb.EventType_EVENT_FILE_CHANGE: {},
		castaipb.EventType_EVENT_MAGIC_WRITE: {},
		castaipb.EventType_EVENT_PROCESS_OOM: {},
	}

	currentOffset := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(timeout):
			var errorMsg strings.Builder

			_, _ = errorMsg.WriteString("not all expected event types found within timeout. missing types:")
			first := true

			for et, _ := range expectedTypes {
				if !first {
					_, _ = errorMsg.WriteString(", ")
				} else {
					first = false
				}

				_, _ = errorMsg.WriteString(et.String())
			}

			return errors.New(errorMsg.String())
		case <-time.Tick(1 * time.Second):
			t.mu.Lock()
			events := t.events
			t.mu.Unlock()

			if len(events) == 0 {
				continue
			}

			for _, event := range events[currentOffset:] {
				delete(expectedTypes, event.EventType)
			}

			currentOffset = len(events)

			fmt.Println("missing event types:", expectedTypes)
			if len(expectedTypes) == 0 {
				return nil
			}
		}
	}
}

func (t *testCASTAIServer) assertEvents(ctx context.Context) error {
	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for received events")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			events := t.events
			t.mu.Unlock()
      fmt.Printf("evaluating %d events\n", len(events))
			for _, e := range events {
				if e.ProcessName == "pause" {
					continue
				}
				if e.EventType == castaipb.EventType_UNKNOWN {
					return fmt.Errorf("unknown event type: %v", e)
				}
				if e.Namespace == "" {
					return fmt.Errorf("missing namespace: %v", e)
				}
				if e.PodName == "" {
					return fmt.Errorf("missing pod: %v", e)
				}
				if e.ContainerName == "" {
					return fmt.Errorf("missing container: %v", e)
				}
				if e.ProcessName == "" {
					return fmt.Errorf("missing process name: %v", e)
				}
				return nil
			}
		}
	}
}

func (t *testCASTAIServer) assertContainerStats(ctx context.Context) error {
	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for received container stats")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			stats := t.containerStats
			t.mu.Unlock()
			if len(stats) > 0 {
				sb1 := stats[0]
				if len(sb1.Items) == 0 {
					return errors.New("missing stat batch items")
				}
				i1 := sb1.Items[0]
				if i1.Namespace == "" {
					return errors.New("missing namespace")
				}
				if i1.PodName == "" {
					return errors.New("missing pod")
				}
				if i1.ContainerName == "" {
					return errors.New("missing container")
				}
				s1 := i1.Stats
				if len(s1) == 0 {
					return errors.New("missing stat items")
				}
				stat := s1[0]
				if stat.Group == castaipb.StatsGroup_STATS_GROUP_UNKNOWN {
					return errors.New("missing stat group")
				}
				if stat.Value == 0 {
					return errors.New("missing stat value")
				}
				return nil
			}
		}
	}
}

func (t *testCASTAIServer) KubernetesDeltaIngest(server castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaIngestServer) error {
	for {
		delta, err := server.Recv()
		if err != nil {
			return err
		}
		t.mu.Lock()
		t.deltaUpdates = append(t.deltaUpdates, delta)
		t.mu.Unlock()
		if err := server.Send(&castaipb.KubernetesDeltaIngestResponse{}); err != nil {
			return err
		}
	}
}

func (t *testCASTAIServer) assertKubernetesDeltas(ctx context.Context) error {
	currentOffset := 0
	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for received kubernetes deltas with all fields set")
		case <-time.Tick(1 * time.Second):
			t.mu.Lock()
			deltas := t.deltaUpdates
			t.mu.Unlock()

      for _, item := range deltas[currentOffset:] {
				if item.ObjectKind != "Deployment" {
					continue
				}
				if item.ObjectName == "" {
					continue
				}
				if item.ObjectUid == "" {
					continue
				}
				if item.ObjectKind == "" {
					continue
				}
				if item.ObjectNamespace == "" {
					continue
				}
				if len(item.ObjectLabels) == 0 {
					continue
				}
				if len(item.ObjectStatus) == 0 {
					continue
				}
				if len(item.ObjectSpec) == 0 {
					continue
				}
				return nil
			}

			currentOffset = len(deltas)
		}
	}
}

func (t *testCASTAIServer) assertImageMetadata(ctx context.Context) error {
	timeout := time.After(20 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for received image metadata")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			md := t.imageMetadatas
			t.mu.Unlock()
			if len(md) > 0 {
				l1 := md[0]
				if l1.ImageId == "" {
					return errors.New("missing image id")
				}
				if l1.ImageName == "" {
					return errors.New("missing image name")
				}
				if len(l1.ConfigFile) == 0 {
					return errors.New("missing config file")
				}
				if len(l1.Packages) == 0 {
					return errors.New("missing packages")
				}
				if len(l1.Architecture) == 0 {
					return errors.New("missing arch")
				}
				return nil
			}
		}
	}
}

func (t *testCASTAIServer) assertKubeBenchReport(ctx context.Context) error {
	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for kube bench")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			items := t.kubeBenchReports
			t.mu.Unlock()
			if len(items) > 0 {
				l1 := items[0]
				if l1.Node == nil {
					return errors.New("missing node")
				}
				if l1.Node.ResourceUid == "" {
					return errors.New("missing node id")
				}
				if l1.Node.NodeName == "" {
					return errors.New("missing node node")
				}
				if len(l1.Controls) == 0 {
					return errors.New("missing controls")
				}
				return nil
			}
		}
	}
}

func (t *testCASTAIServer) assertKubeLinter(ctx context.Context) error {
	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting kube linter")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			items := t.kubeLinterReports
			t.mu.Unlock()
			if len(items) > 0 {
				l1 := items[0]
				if len(l1.Checks) == 0 {
					return errors.New("missing linter checks")
				}
				return nil
			}
		}
	}
}
