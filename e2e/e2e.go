package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/samber/lo"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	imageTag = pflag.String("image-tag", "", "Kvisor docker image tag")
	timeout  = pflag.Duration("timeout", 180*time.Second, "Test timeout")
	ns       = pflag.String("ns", "kvisor-e2e", "Namespace")
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
	inClusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(inClusterConfig)
	if err != nil {
		return err
	}

	srv := &testCASTAIServer{clientset: clientset}
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

	fmt.Println("🙏waiting for config")
	if err := srv.assertConfig(ctx); err != nil {
		return fmt.Errorf("assert config: %w", err)
	}

	fmt.Println("🙏waiting for events")
	if err := srv.assertEvents(ctx); err != nil {
		return fmt.Errorf("assert events: %w", err)
	}
	// After events assert is done we should cleanup and stop persisting them to reduce e2e test memory usage.
	srv.eventsAsserted = true
	srv.events = nil

	fmt.Println("🙏waiting for netflows")
	if err := srv.assertNetflows(ctx); err != nil {
		return fmt.Errorf("assert netflows: %w", err)
	}

	fmt.Println("🙏waiting for container stats")
	if err := srv.assertContainerStats(ctx); err != nil {
		return fmt.Errorf("assert container stats: %w", err)
	}

	fmt.Println("🙏waiting for kubernetes deltas")
	if err := srv.assertKubernetesDeltas(ctx); err != nil {
		return fmt.Errorf("assert k8s deltas: %w", err)
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

	fmt.Println("🙏waiting for flogs")
	if err := srv.assertLogs(ctx); err != nil {
		return fmt.Errorf("assert logs: %w", err)
	}

	fmt.Println("🙏waiting for process tree events")
	if err := srv.assertProcessTreeEvents(ctx); err != nil {
		return fmt.Errorf("assert process tree events: %w", err)
	}

	fmt.Println("👌e2e finished")

	return nil
}

func installChart(ns, imageTag string) ([]byte, error) {
	fmt.Printf("installing kvisor chart with image tag %q\n", imageTag)
	repo := "ghcr.io/castai/kvisor/kvisor"
	if imageTag == "local" {
		repo = "kvisor"
	}

	grpcAddr := fmt.Sprintf("%s:8443", os.Getenv("POD_IP"))
	//nolint:gosec
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf(
		`helm upgrade --install kvisor-e2e ./charts/kvisor \
  -n %s --create-namespace \
  --set image.repository=%s \
  --set image.tag=%s \
  --set agent.enabled=true \
  --set agent.extraArgs.log-level=debug \
  --set agent.extraArgs.container-stats-enabled=true \
  --set agent.extraArgs.container-stats-scrape-interval=5s \
  --set agent.extraArgs.castai-server-insecure=true \
  --set agent.extraArgs.ebpf-events-enabled=true \
  --set agent.extraArgs.file-hash-enricher-enabled=true \
  --set agent.extraArgs.signature-socks5-detection-enabled=true \
  --set agent.extraArgs.signature-stdio-via-sock-enabled=true \
  --set agent.extraArgs.netflow-enabled=true \
  --set agent.extraArgs.netflow-sample-submit-interval-seconds=5 \
  --set agent.extraArgs.process-tree-enabled=true \
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
	clientset *kubernetes.Clientset

	mu                sync.Mutex
	containerStats    []*castaipb.ContainerStatsBatch
	events            []*castaipb.Event
	eventsAsserted    bool
	logs              []*castaipb.LogEvent
	deltaUpdates      []*castaipb.KubernetesDeltaItem
	imageMetadatas    []*castaipb.ImageMetadata
	kubeBenchReports  []*castaipb.KubeBenchReport
	kubeLinterReports []*castaipb.KubeLinterReport
	processTreeEvents []*castaipb.ProcessTreeEvent
	controllerConfig  *castaipb.ControllerConfig
	agentConfig       *castaipb.AgentConfig
	netflows          []*castaipb.Netflow
}

func (t *testCASTAIServer) ProcessEventsWriteStream(server castaipb.RuntimeSecurityAgentAPI_ProcessEventsWriteStreamServer) error {
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
		data, err := protojson.Marshal(event)
		if err != nil {
			fmt.Println("received process tree event (cannot marshall to json):", event)
		} else {
			fmt.Println("received process tree event:", string(data))
		}
		t.mu.Lock()
		t.processTreeEvents = append(t.processTreeEvents, event)
		t.mu.Unlock()
	}
}

func (t *testCASTAIServer) NetflowWriteStream(server castaipb.RuntimeSecurityAgentAPI_NetflowWriteStreamServer) error {
	for {
		msg, err := server.Recv()
		if err != nil {
			return err
		}
		fmt.Printf("received netflow: %+v\n", msg)
		t.mu.Lock()
		t.netflows = append(t.netflows, msg)
		t.mu.Unlock()
	}
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

func (t *testCASTAIServer) GetConfiguration(ctx context.Context, req *castaipb.GetConfigurationRequest) (*castaipb.GetConfigurationResponse, error) {
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

	t.mu.Lock()
	defer t.mu.Unlock()
	if v := req.GetController(); v != nil {
		t.controllerConfig = v
	}
	if v := req.GetAgent(); v != nil {
		t.agentConfig = v
	}

	fmt.Printf("received configs:\ncontroller=%v\n agent=%v\n", t.controllerConfig, t.agentConfig)

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
		if !t.eventsAsserted {
			t.mu.Lock()
			t.events = append(t.events, event)
			t.mu.Unlock()
		}
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

	r := newAssertions()

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
				r.NotEmpty(l1.Msg)

				for _, l := range logs {
					if strings.Contains(l.Msg, "panic") {
						return fmt.Errorf("received logs contains panic error: %s", l.Msg)
					}
				}

				return r.error()
			}
		}
	}
}

func (t *testCASTAIServer) assertProcessTreeEvents(ctx context.Context) error {
	timeout := time.After(10 * time.Second)

	expectedTypes := map[castaipb.ProcessAction]struct{}{
		castaipb.ProcessAction_PROCESS_ACTION_FORK: {},
		castaipb.ProcessAction_PROCESS_ACTION_EXEC: {},
		castaipb.ProcessAction_PROCESS_ACTION_EXIT: {},
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			var errorMsg strings.Builder

			_, _ = errorMsg.WriteString("not all expected process tree event types found within timeout. missing types:")
			first := true

			for et := range expectedTypes {
				if !first {
					_, _ = errorMsg.WriteString(", ")
				} else {
					first = false
				}

				_, _ = errorMsg.WriteString(et.String())
			}
			return errors.New(errorMsg.String())
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			processTreeEvents := t.processTreeEvents
			t.processTreeEvents = []*castaipb.ProcessTreeEvent{}
			t.mu.Unlock()

			if len(processTreeEvents) > 0 {
				for _, event := range processTreeEvents {
					for _, pe := range event.Events {
						delete(expectedTypes, pe.Action)
					}

					// In order to speed things up we will short circuit the when we all expected events have been found.
					if len(expectedTypes) == 0 {
						return nil
					}
				}

				if len(expectedTypes) == 0 {
					return nil
				}
			}
		}
	}
}

func (t *testCASTAIServer) KubernetesDeltaIngest(server castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaIngestServer) error {
	panic("should not be called")
}

func (t *testCASTAIServer) KubernetesDeltaBatchIngest(server castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaBatchIngestServer) error {
	for {
		delta, err := server.Recv()
		if err != nil {
			return err
		}
		t.mu.Lock()
		t.deltaUpdates = append(t.deltaUpdates, delta.Items...)
		t.mu.Unlock()
		if err := server.Send(&castaipb.KubernetesDeltaIngestResponse{}); err != nil {
			return err
		}
	}
}

const (
	ExecUpperLayer    uint32 = 1 << 0
	ExecMemfd         uint32 = 1 << 1
	ExecTmpfs         uint32 = 1 << 2
	ExecDroppedBinary uint32 = 1 << 3
)

func (t *testCASTAIServer) validateExecEvents() error {
	var foundExecWithHash bool
	var foundExecFromUpperLayer bool
	var foundExecTmpfs bool
	var foundExecDroppedBinary bool

	for _, e := range t.events {
		if e.EventType == castaipb.EventType_EVENT_EXEC {
			if e.GetExec().HashSha256 != nil {
				foundExecWithHash = true
			}

			flags := e.GetExec().Flags
			originalFileFlags := flags >> 16

			if (originalFileFlags | ExecUpperLayer) > 0 {
				foundExecFromUpperLayer = true
			}

			if (originalFileFlags | ExecTmpfs) > 0 {
				foundExecTmpfs = true
			}

			if (originalFileFlags | ExecDroppedBinary) > 0 {
				foundExecDroppedBinary = true
			}
		}
	}

	if !foundExecWithHash {
		return errors.New("expected at least one exec event with hash set")
	}
	if !foundExecFromUpperLayer {
		return errors.New("expected at least one exec event from upper layer")
	}
	if !foundExecTmpfs {
		return errors.New("expected at least one exec event from tmpfs")
	}
	if !foundExecDroppedBinary {
		return errors.New("expected at least one exec event from dropped binary")
	}

	return nil
}

func (t *testCASTAIServer) validateSignatureEvents(ctx context.Context, timeout time.Duration) error {
	expectedTypes := map[castaipb.SignatureEventID]struct{}{
		castaipb.SignatureEventID_SIGNATURE_SOCKS5_DETECTED: {},
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

			for et := range expectedTypes {
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
				signatureID := event.GetSignature().GetMetadata().GetId()
				if signatureID == castaipb.SignatureEventID_SIGNATURE_UNKNOWN {
					continue
				}

				delete(expectedTypes, signatureID)
			}

			currentOffset = len(events)

			fmt.Println("missing signature types:", expectedTypes)
			if len(expectedTypes) == 0 {
				return nil
			}
		}
	}
}

type eventValidatorFunc func(e *castaipb.Event) error

func (t *testCASTAIServer) validateEvents(ctx context.Context, timeout time.Duration) error {
	eventsValidators := map[castaipb.EventType]eventValidatorFunc{
		castaipb.EventType_EVENT_EXEC: func(e *castaipb.Event) error {
			if e.GetExec().Path == "" {
				return errors.New("missing exec path")
			}
			return nil
		},
		castaipb.EventType_EVENT_DNS: func(e *castaipb.Event) error {
			if e.GetDns().DNSQuestionDomain == "" {
				return errors.New("missing dns question domain")
			}
			return nil
		},
		castaipb.EventType_EVENT_TCP_CONNECT: func(e *castaipb.Event) error {
			tuple := e.GetTuple()
			if _, ok := netip.AddrFromSlice(tuple.SrcIp); !ok {
				return fmt.Errorf("invalid address %v", string(tuple.SrcIp))
			}
			if _, ok := netip.AddrFromSlice(tuple.DstIp); !ok {
				return fmt.Errorf("invalid address %v", string(tuple.SrcIp))
			}
			return nil
		},
		castaipb.EventType_EVENT_TCP_LISTEN: func(e *castaipb.Event) error {
			tuple := e.GetTuple()
			if _, ok := netip.AddrFromSlice(tuple.SrcIp); !ok {
				return fmt.Errorf("invalid address %v", string(tuple.SrcIp))
			}
			if tuple.SrcPort == 0 {
				return fmt.Errorf("invalid port: 0")
			}
			return nil
		},
		castaipb.EventType_EVENT_MAGIC_WRITE: func(e *castaipb.Event) error {
			return nil
		},
		castaipb.EventType_EVENT_PROCESS_OOM: func(e *castaipb.Event) error {
			return nil
		},
	}
	expectedTypes := lo.KeyBy(lo.Keys(eventsValidators), func(item castaipb.EventType) castaipb.EventType {
		return item
	})

	currentOffset := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(timeout):
			var errorMsg strings.Builder

			_, _ = errorMsg.WriteString("not all expected event types found within timeout. missing types:")
			first := true

			for et := range expectedTypes {
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
				if validator, found := eventsValidators[event.EventType]; found {
					if err := validator(event); err != nil {
						return err
					}
				}
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
	if err := func() error {
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
	}(); err != nil {
		return err
	}

	validateTimeout := 30 * time.Second
	fmt.Printf("🧐validating events (timeout %s)\n", validateTimeout)
	if err := t.validateEvents(ctx, validateTimeout); err != nil {
		return fmt.Errorf("validate events: %w", err)
	}

	fmt.Println("🧐validating exec events")
	if err := t.validateExecEvents(); err != nil {
		return fmt.Errorf("validate exec events: %w", err)
	}

	fmt.Println("🧐validating signature events")
	if err := t.validateSignatureEvents(ctx, validateTimeout); err != nil {
		return fmt.Errorf("validate signature events: %w", err)
	}
	return nil
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

func (t *testCASTAIServer) assertConfig(ctx context.Context) error {
	timeout := time.After(10 * time.Second)

	r := newAssertions()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting controller and agent configs")
		case <-time.Tick(1 * time.Second):
			t.mu.Lock()
			ctrlConfig := t.controllerConfig
			agentConfig := t.agentConfig
			t.mu.Unlock()

			if ctrlConfig == nil {
				fmt.Println("no controller config yet")
				continue
			}
			if agentConfig == nil {
				fmt.Println("no agent config yet")
				continue
			}
			r.NotEmpty(ctrlConfig.Version)
			r.NotEmpty(ctrlConfig.ChartVersion)
			r.True(ctrlConfig.ImageScan.Enabled)
			r.True(ctrlConfig.Linter.Enabled)
			r.True(ctrlConfig.Delta.Enabled)
			r.True(ctrlConfig.KubeBench.Enabled)

			r.NotEmpty(agentConfig.Version)

			return r.error()
		}
	}
}

func (t *testCASTAIServer) assertKubernetesDeltas(ctx context.Context) error {
	currentOffset := 0
	timeout := time.After(10 * time.Second)

	allDeployments, err := t.clientset.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing k8s pods: %w", err)
	}

	allServices, err := t.clientset.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing k8s services: %w", err)
	}

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

			// Some validation for received deltas counts.
			deltaDeploymentsCount := lo.CountBy(deltas, func(item *castaipb.KubernetesDeltaItem) bool {
				return item.ObjectKind == "Deployment"
			})
			if deltaDeploymentsCount < len(allDeployments.Items) {
				fmt.Printf("expected at least %d deployments, got %d\n", deltaDeploymentsCount, len(allDeployments.Items))
				continue
			}
			deltaServicesCount := lo.CountBy(deltas, func(item *castaipb.KubernetesDeltaItem) bool {
				return item.ObjectKind == "Service"
			})
			if deltaServicesCount < len(allServices.Items) {
				fmt.Printf("expected at least %d services, got %d\n", deltaServicesCount, len(allServices.Items))
				continue
			}

			// Some validation for received delta fields.
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
	timeout := time.After(30 * time.Second)
	r := newAssertions()
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
				fmt.Printf("asserting image metadata:\n%v\n", l1)
				r.NotEmpty(l1.ImageId, "missing image id")
				r.NotEmpty(l1.ImageName, "missing image name")
				r.NotEmpty(l1.ConfigFile, "missing image config")
				r.NotEmpty(l1.Packages, "missing image packages")
				return r.error()
			}
		}
	}
}

func (t *testCASTAIServer) assertKubeBenchReport(ctx context.Context) error {
	timeout := time.After(30 * time.Second)
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

func (t *testCASTAIServer) assertNetflows(ctx context.Context) error {
	timeout := time.After(15 * time.Second)
	r := newAssertions()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for netflows")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			items := t.netflows
			t.mu.Unlock()
			if len(items) > 0 {
				f1 := items[0]
				r.NotEmpty(f1.Timestamp)
				r.NotEmpty(f1.Namespace)
				r.NotEmpty(f1.PodName)
				r.NotEmpty(f1.ContainerName)
				r.NotEmpty(f1.ProcessName)
				r.NotEmpty(f1.Addr)
				r.NotEmpty(f1.Destinations)
				d1 := f1.Destinations[0]
				r.NotEmpty(d1.Addr)
				r.NotEmpty(d1.Port)
				r.NotEmpty(d1.TxBytes + d1.RxBytes)
				r.NotEmpty(d1.TxPackets + d1.RxPackets)
				return r.error()
			}
		}
	}
}

type testingT struct {
	failed bool
	errors []error
}

func (t *testingT) Errorf(format string, args ...interface{}) {
	t.errors = append(t.errors, fmt.Errorf(format, args...))
}

func (t *testingT) FailNow() {
	t.failed = true
}

type assertions struct {
	*assert.Assertions
	t *testingT
}

func (a *assertions) error() error {
	if a.t.failed {
		return errors.Join(a.t.errors...)
	}
	return nil
}

func newAssertions() *assertions {
	t := &testingT{}
	r := assert.New(t)
	return &assertions{
		Assertions: r,
		t:          t,
	}
}
