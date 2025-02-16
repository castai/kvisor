package main

import (
	"context"
	"encoding/json"
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
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip" // Register gzip compressor.
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
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

	srv := &testCASTAIServer{clientset: clientset, testStartTime: time.Now().UTC(), outputReceivedData: false}
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

	fmt.Println("🙏waiting for ipv4 netflows")
	if err := srv.assertNetflows(ctx, "echo-a-ipv4", unix.AF_INET); err != nil {
		return fmt.Errorf("assert ipv4 netflows: %w", err)
	}
	srv.netflows = nil

	fmt.Println("🙏waiting for ipv6 netflows")
	if err := srv.assertNetflows(ctx, "echo-a-ipv6", unix.AF_INET6); err != nil {
		return fmt.Errorf("assert ipv6 netflows: %w", err)
	}
	srv.netflowsAsserted = true
	srv.netflows = nil

	fmt.Println("🙏waiting for container stats")
	if err := srv.assertContainerStats(ctx); err != nil {
		return fmt.Errorf("assert container stats: %w", err)
	}
	srv.statsAsserted = true
	srv.stats = nil

	fmt.Println("🙏waiting for kube bench")
	if err := srv.assertKubeBenchReport(ctx); err != nil {
		return fmt.Errorf("assert kube bench: %w", err)
	}

	fmt.Println("🙏waiting for kube linter")
	if err := srv.assertKubeLinter(ctx); err != nil {
		return fmt.Errorf("assert kube linter: %w", err)
	}
	srv.kubeLinterReports = nil

	fmt.Println("🙏waiting for image metadata")
	if err := srv.assertImageMetadata(ctx); err != nil {
		return fmt.Errorf("assert image metadata: %w", err)
	}
	srv.imageMetadatas = nil

	fmt.Println("🙏waiting for flogs")
	if err := srv.assertLogs(ctx); err != nil {
		return fmt.Errorf("assert logs: %w", err)
	}
	srv.logs = nil

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
  --set agent.extraArgs.stats-enabled=true \
  --set agent.extraArgs.stats-scrape-interval=5s \
  --set agent.extraArgs.castai-server-insecure=true \
  --set agent.extraArgs.ebpf-events-enabled=true \
  --set agent.extraArgs.file-hash-enricher-enabled=true \
  --set agent.extraArgs.signature-socks5-detection-enabled=true \
  --set agent.extraArgs.netflow-enabled=true \
  --set agent.extraArgs.netflow-sample-submit-interval-seconds=5 \
  --set agent.extraArgs.netflow-export-interval=5s \
  --set agent.extraArgs.process-tree-enabled=true \
  --set agent.extraArgs.ebpf-events-include-pod-labels="name\,app\,app.kubernetes.io/name\,app.kubernetes.io/component" \
  --set agent.extraArgs.ebpf-events-include-pod-annotations="cast.ai\,checksum/config"  \
  --set controller.extraArgs.castai-server-insecure=true \
  --set controller.extraArgs.log-level=debug \
  --set controller.extraArgs.image-scan-enabled=true \
  --set controller.extraArgs.image-scan-interval=5s \
  --set controller.extraArgs.image-scan-init-delay=5s \
  --set controller.extraArgs.image-concurrent-scans=3 \
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

	testStartTime time.Time

	mu                     sync.Mutex
	stats                  []*castaipb.StatsBatch
	statsAsserted          bool
	events                 []*castaipb.Event
	containerEventsBatches []*castaipb.ContainerEventsBatch
	eventsAsserted         bool
	logs                   []*castaipb.LogEvent
	imageMetadatas         []*castaipb.ImageMetadata
	kubeBenchReports       []*castaipb.KubeBenchReport
	kubeLinterReports      []*castaipb.KubeLinterReport
	processTreeEvents      []*castaipb.ProcessTreeEvent
	controllerConfig       []byte
	agentConfig            []byte
	netflows               []*castaipb.Netflow
	netflowsAsserted       bool
	outputReceivedData     bool
}

func (t *testCASTAIServer) ContainerEventsBatchWriteStream(g grpc.ClientStreamingServer[castaipb.ContainerEventsBatch, castaipb.WriteStreamResponse]) error {
	md, ok := metadata.FromIncomingContext(g.Context())
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
		event, err := g.Recv()
		if err != nil {
			return err
		}
		if t.eventsAsserted {
			continue
		}
		data, err := protojson.Marshal(event)
		if err != nil {
			fmt.Println("received container events batch(cannot marshall to json):", event)
		} else if t.outputReceivedData {
			fmt.Println("received container events batch", string(data))
		}
		t.mu.Lock()
		t.containerEventsBatches = append(t.containerEventsBatches, event)
		t.mu.Unlock()
	}
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
		} else if t.outputReceivedData {
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
		if t.netflowsAsserted {
			continue
		}
		if t.outputReceivedData {
			fmt.Printf("received netflow: %+v\n", msg)
		}
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

	fmt.Printf("received image metadata, image_name=%s\n", imageMetadata.ImageName)
	t.imageMetadatas = append(t.imageMetadatas, imageMetadata)

	return &castaipb.ImageMetadataIngestResponse{}, nil
}

func (t *testCASTAIServer) GetSyncState(ctx context.Context, request *castaipb.GetSyncStateRequest) (*castaipb.GetSyncStateResponse, error) {
	return &castaipb.GetSyncStateResponse{}, nil
}

func (t *testCASTAIServer) UpdateSyncState(ctx context.Context, request *castaipb.UpdateSyncStateRequest) (*castaipb.UpdateSyncStateResponse, error) {
	return &castaipb.UpdateSyncStateResponse{}, nil
}

func (t *testCASTAIServer) StatsWriteStream(server castaipb.RuntimeSecurityAgentAPI_StatsWriteStreamServer) error {
	for {
		msg, err := server.Recv()
		if err != nil {
			return err
		}
		if t.statsAsserted {
			continue
		}
		if t.outputReceivedData {
			fmt.Println("received stats:", len(msg.Items))
		}
		t.mu.Lock()
		t.stats = append(t.stats, msg)
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
	if t.outputReceivedData {
		fmt.Printf("received configs:\ncontroller=%v\n agent=%v\n", string(t.controllerConfig), string(t.agentConfig))
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
		if t.outputReceivedData {
			fmt.Printf("received event: %+v\n", event)
		}
		if t.eventsAsserted {
			continue
		}
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
		if t.outputReceivedData {
			fmt.Println("received log:", event)
		}
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

func (t *testCASTAIServer) KubernetesDeltaIngest(server castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaIngestServer) error {
	panic("should not be called")
}

func (t *testCASTAIServer) KubernetesDeltaBatchIngest(server castaipb.RuntimeSecurityAgentAPI_KubernetesDeltaBatchIngestServer) error {
	panic("should not be called")
}

const (
	ExecUpperLayer    uint32 = 1 << 0
	ExecMemfd         uint32 = 1 << 1
	ExecTmpfs         uint32 = 1 << 2
	ExecDroppedBinary uint32 = 1 << 3
)

type eventValidator struct {
	name       string
	assertions *assertions
	validate   func(v *eventValidator, batch *castaipb.ContainerEvents) error
	passed     bool
}

func (v *eventValidator) finish(err error) {
	if v.passed {
		return
	}
	v.passed = err == nil
}

var errValidatorSkipped = errors.New("skipped")

func (t *testCASTAIServer) validateEvents(ctx context.Context, timeout time.Duration) error {
	validators := []*eventValidator{
		{
			name:       "process tree events",
			assertions: newAssertions(),
			validate: func(v *eventValidator, batch *castaipb.ContainerEvents) (err error) {
				defer v.finish(err)

				if batch.WorkloadName != "magic-write-generator" {
					return errValidatorSkipped
				}

				var foundExec, foundFork, foundExit bool
				for _, item := range batch.Items {
					if item.EventType == castaipb.EventType_EVENT_EXEC {
						foundExec = true
					}
					if item.EventType == castaipb.EventType_EVENT_PROCESS_FORK {
						foundFork = true
					}
					if item.EventType == castaipb.EventType_EVENT_PROCESS_EXIT {
						foundExit = true
					}
				}
				if !foundExec {
					return errors.New("no exec")
				}
				if !foundFork {
					return errors.New("no fork")
				}
				if !foundExit {
					return errors.New("no exit")
				}
				return nil
			},
		},
		{
			name:       "dns event + tcp event",
			assertions: newAssertions(),
			validate: func(v *eventValidator, batch *castaipb.ContainerEvents) (err error) {

				defer v.finish(err)
				r := v.assertions
				if batch.WorkloadName != "dns-generator" {
					return errValidatorSkipped
				}

				r.NotEmpty(batch.WorkloadUid)
				r.Equal(castaipb.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT, batch.WorkloadKind)
				r.Contains(batch.PodName, "dns-generator")
				r.Equal("dns-generator", batch.ContainerName)
				r.Equal("kvisor-e2e", batch.Namespace)
				r.Equal(map[string]string{"cast.ai/e2e": "e2e"}, batch.ObjectAnnotations)
				r.Equal(map[string]string{"app": "dns-generator"}, batch.ObjectLabels)
				r.NotEmpty(batch.NodeName)
				r.NotEmpty(batch.PodUid)
				r.NotEmpty(batch.ContainerId)
				r.NotEmpty(batch.CgroupId)

				var foundDNS bool
				var foundTCP bool
				for _, item := range batch.Items {
					if item.EventType == castaipb.EventType_EVENT_DNS {
						r.NotEmpty(item.Pid)
						r.NotEmpty(item.Ppid)
						r.NotEmpty(item.HostPid)
						r.NotEmpty(item.ProcessStartTime)
						r.NotEmpty(item.ProcessParentStartTime)
						r.NotEmpty(item.ProcessName)
						r.NotEmpty(item.Timestamp)
						r.Equal("google.com", item.GetDns().DNSQuestionDomain)
						foundDNS = true
					}
					if item.EventType == castaipb.EventType_EVENT_TCP_CONNECT {
						r.NotEmpty(item.Pid)
						r.NotEmpty(item.Ppid)
						r.NotEmpty(item.HostPid)
						r.NotEmpty(item.ProcessStartTime)
						r.NotEmpty(item.ProcessParentStartTime)
						r.NotEmpty(item.ProcessName)
						r.NotEmpty(item.Timestamp)
						r.NotEmpty(item.GetTuple().SrcPort)
						r.NotEmpty(item.GetTuple().SrcIp)
						r.Equal(443, item.GetTuple().DstPort)
						r.NotEmpty(item.GetTuple().DstIp)
						if _, ok := netip.AddrFromSlice(item.GetTuple().SrcIp); !ok {
							return fmt.Errorf("invalid src address %v", string(item.GetTuple().SrcIp))
						}
						if _, ok := netip.AddrFromSlice(item.GetTuple().DstIp); !ok {
							return fmt.Errorf("invalid dst address %v", string(item.GetTuple().DstIp))
						}
						foundTCP = true
					}
				}
				if !foundDNS {
					return errors.New("missing dns event")
				}
				if !foundTCP {
					return errors.New("missing tcp")
				}
				return r.error()
			},
		},
		{
			name:       "magic write + dropped and executed binary",
			assertions: newAssertions(),
			validate: func(v *eventValidator, batch *castaipb.ContainerEvents) (err error) {
				defer v.finish(err)

				if batch.WorkloadName != "magic-write-generator" {
					return errValidatorSkipped
				}

				r := v.assertions
				r.NotEmpty(batch.WorkloadUid)
				r.Equal(castaipb.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT, batch.WorkloadKind)
				r.Contains(batch.PodName, "magic-write-generator")
				r.Equal("magic-write-generator", batch.ContainerName)
				r.Equal("kvisor-e2e", batch.Namespace)
				r.Equal(map[string]string{"cast.ai/e2e": "e2e"}, batch.ObjectAnnotations)
				r.Equal(map[string]string{"app": "magic-write-generator"}, batch.ObjectLabels)
				r.NotEmpty(batch.NodeName)
				r.NotEmpty(batch.PodUid)
				r.NotEmpty(batch.ContainerId)
				r.NotEmpty(batch.CgroupId)

				var foundExecWithHash bool
				var foundExecFromUpperLayer bool
				var foundExecTmpfs bool
				var foundExecDroppedBinary bool
				var foundMagicWrite bool

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
						r.Equal("tar_executable", e.GetExec().Path)
						r.NotEmpty(e.GetExec().Args)
					}
					if e.EventType == castaipb.EventType_EVENT_MAGIC_WRITE {
						foundMagicWrite = true
						r.NotEmpty(e.GetFile().Path)
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
				if !foundMagicWrite {
					return errors.New("expected at least on magic write")
				}
				return r.error()
			},
		},
		{
			name:       "ssh + socks5",
			assertions: newAssertions(),
			validate: func(v *eventValidator, batch *castaipb.ContainerEvents) (err error) {
				if batch.WorkloadName != "ssh-client" {
					return errValidatorSkipped
				}

				r := v.assertions
				r.NotEmpty(batch.WorkloadUid)
				r.Equal(castaipb.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT, batch.WorkloadKind)
				r.Contains(batch.PodName, "ssh-client")
				r.Equal("ssh-client", batch.ContainerName)
				r.Equal("kvisor-e2e", batch.Namespace)
				r.Equal(map[string]string{"cast.ai/e2e": "e2e"}, batch.ObjectAnnotations)
				r.Equal(map[string]string{"name": "ssh-client"}, batch.ObjectLabels)
				r.NotEmpty(batch.NodeName)
				r.NotEmpty(batch.PodUid)
				r.NotEmpty(batch.ContainerId)
				r.NotEmpty(batch.CgroupId)

				var foundSSH bool
				var foundSocks5 bool

				for _, e := range t.events {
					if e.EventType == castaipb.EventType_EVENT_SSH {
						foundSSH = true
						r.NotEmpty(e.GetSsh().Tuple.SrcIp)
						r.NotEmpty(e.GetSsh().Tuple.DstIp)
					}
					if e.EventType == castaipb.EventType_EVENT_SIGNATURE {
						if e.GetSignature().Metadata.Id == castaipb.SignatureEventID_SIGNATURE_SOCKS5_DETECTED {
							foundSocks5 = true
							r.NotEmpty(e.GetSignature().Finding.GetSocks5Detected().Address)
						}
					}
				}

				if !foundSSH {
					return errors.New("expected at least ssh event")
				}
				if !foundSocks5 {
					return errors.New("expected at least socks5 event")
				}
				return r.error()
			},
		},
	}

	validateAll := func() error {
		t.mu.Lock()
		defer t.mu.Unlock()

		var errs []error
		var passedCount int
		for _, validator := range validators {
			passedCount++
			for _, batch := range t.containerEventsBatches {
				for _, item := range batch.Items {
					if err := validator.validate(validator, item); err != nil {
						errs = append(errs, err)
					}
				}
			}
		}
		if passedCount == len(validators) {
			return nil
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
		return errors.New("did not pass all validators")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(timeout):
			return validateAll()
		case <-time.Tick(1 * time.Second):
			if err := validateAll(); err != nil {
				fmt.Printf("validators did not pass yet: %v\n", err)
				continue
			}
			return nil
		}
	}

}

func (t *testCASTAIServer) assertEvents(ctx context.Context) error {
	validateTimeout := 30 * time.Second
	fmt.Printf("🧐validating events (timeout %s)\n", validateTimeout)
	if err := t.validateEvents(ctx, validateTimeout); err != nil {
		return fmt.Errorf("validate events: %w", err)
	}

	return nil
}

func (t *testCASTAIServer) assertContainerStats(ctx context.Context) error {
	timeout := time.After(10 * time.Second)

	nodeStatsAsserted := false
	containerStatsAsserted := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for received container stats")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			stats := t.stats
			t.mu.Unlock()
			if len(stats) == 0 {
				continue
			}

			sb1 := stats[0]
			if len(sb1.Items) == 0 {
				return errors.New("missing stat batch items")
			}

			for _, st := range stats {
				for _, item := range st.Items {
					cont := item.GetContainer()
					if cont != nil {
						if cont.Namespace == "" {
							return errors.New("missing namespace")
						}
						if cont.PodName == "" {
							return errors.New("missing pod")
						}
						if cont.ContainerName == "" {
							return errors.New("missing container")
						}
						if cont.NodeName == "" {
							return fmt.Errorf("missing node: %+v", cont)
						}
						cpuUsage := cont.CpuStats.TotalUsage
						memUsage := cont.MemoryStats.Usage.Usage
						if cpuUsage == 0 && memUsage == 0 {
							return errors.New("missing cpu or memory usage")
						}
						containerStatsAsserted = true
					}
					node := item.GetNode()
					if node != nil {
						if node.NodeName == "" {
							return errors.New("missing node name")
						}
						if node.MemoryStats.Usage.Usage == 0 {
							return errors.New("missing node memory usage")
						}
						nodeStatsAsserted = true
					}
				}
			}

			if containerStatsAsserted && nodeStatsAsserted {
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
			ctrlConfigBytes := t.controllerConfig
			agentConfigBytes := t.agentConfig
			t.mu.Unlock()

			if len(ctrlConfigBytes) == 0 {
				fmt.Println("no controller config yet")
				continue
			}
			if len(agentConfigBytes) == 0 {
				fmt.Println("no agent config yet")
				continue
			}
			ctrlConfig := map[string]any{}
			agentConfig := map[string]any{}
			if err := json.Unmarshal(ctrlConfigBytes, &ctrlConfig); err != nil {
				return err
			}
			if err := json.Unmarshal(agentConfigBytes, &agentConfig); err != nil {
				return err
			}
			r.NotEmpty(ctrlConfig["Version"])
			r.NotEmpty(ctrlConfig["ChartVersion"])
			r.NotEmpty(agentConfig["Version"])

			return r.error()
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

func (t *testCASTAIServer) assertNetflows(ctx context.Context, workload string, family uint16) error {
	timeout := time.After(30 * time.Second)
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
			for _, f1 := range items {
				for _, d1 := range f1.Destinations {
					if d1.WorkloadName != workload || d1.TxBytes == 0 || d1.RxBytes == 0 {
						continue
					}
					r.NotEmpty(f1.Timestamp)
					r.NotEmpty(f1.Namespace)
					r.NotEmpty(f1.PodName)
					r.NotEmpty(f1.ContainerName)
					r.NotEmpty(f1.ProcessName)
					r.NotEmpty(f1.Addr)
					r.NotEmpty(f1.Destinations)
					r.Equal(family, getAddrFamily(d1.Addr))
					r.NotEmpty(d1.Port)
					r.NotEmpty(d1.WorkloadKind)
					r.NotEmpty(d1.WorkloadName)
					r.NotEmpty(d1.Namespace)
					r.NotEmpty(d1.TxBytes + d1.RxBytes)
					r.NotEmpty(d1.TxPackets + d1.RxPackets)
					return r.error()
				}
			}
		}
	}
}

func getAddrFamily(data []byte) int {
	switch len(data) {
	case 4:
		return unix.AF_INET
	case 16:
		return unix.AF_INET6
	}
	return 0 // unknown family
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
