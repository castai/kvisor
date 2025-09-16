package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hamba/avro/v2"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip" // Register gzip compressor.
	"google.golang.org/grpc/metadata"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/pipeline"
	metricspb "github.com/castai/metrics/api/v1beta"
)

type StorageMetricsBatch struct {
	Collection    string
	Rows          uint64
	Schema        []byte
	Metrics       []byte
	SkipTimestamp bool
	Timestamp     time.Time
}

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
	metricspb.RegisterIngestionAPIServer(s, srv)
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

	fmt.Println("🙏waiting for initial process tree")
	if err := srv.assertProcessTree(ctx); err != nil {
		return fmt.Errorf("assert initial process tree: %w", err)
	}
	srv.processTreeEvents = nil

	fmt.Println("🙏waiting for events")
	if err := srv.assertEvents(ctx); err != nil {
		return fmt.Errorf("assert events: %w", err)
	}
	// After events assert is done we should cleanup and stop persisting them to reduce e2e test memory usage.
	srv.eventsAsserted = true

	fmt.Println("🙏waiting for ipv4 netflows")
	if err := srv.assertNetflows(ctx, "echo-a-ipv4", unix.AF_INET); err != nil {
		return fmt.Errorf("assert ipv4 netflows: %w", err)
	}
	srv.netflows = nil

	fmt.Println("🙏waiting for ipv6 netflows")
	if err := srv.assertNetflows(ctx, "echo-a-ipv6", unix.AF_INET6); err != nil {
		return fmt.Errorf("assert ipv6 netflows: %w", err)
	}

	fmt.Println("🙏waiting for iperf netflows")
	if err := srv.assertIperfNetflows(ctx); err != nil {
		return err
	}
	srv.netflowsAsserted = true
	srv.netflows = nil

	fmt.Println("🙏waiting for container stats")
	if err := srv.assertContainerStats(ctx); err != nil {
		return fmt.Errorf("assert container stats: %w", err)
	}

	fmt.Println("🙏waiting for kvisor components resource usage")
	if err := srv.assertKvisorResourceUsage(ctx); err != nil {
		return fmt.Errorf("assert kvisor components resource usage: %w", err)
	}
	srv.containerStatsAsserterd = true
	srv.containerStats = nil

	fmt.Println("🙏waiting for node stats")
	if err := srv.assertNodeStats(ctx); err != nil {
		return fmt.Errorf("assert node stats: %w", err)
	}
	srv.nodeStatsAsserted = true
	srv.nodeStats = nil

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

	fmt.Println("🙏waiting for storage metrics")
	if err := srv.assertStorageMetrics(ctx); err != nil {
		return fmt.Errorf("assert storage metrics: %w", err)
	}
	srv.storageMetricsAsserted = true
	srv.storageMetrics = nil

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
  --set agent.extraArgs.storage-stats-enabled=true \
  --set agent.extraArgs.stats-file-access-enabled=true \
  --set agent.extraArgs.stats-scrape-interval=1s \
  --set agent.extraArgs.castai-server-insecure=true \
  --set agent.extraArgs.ebpf-events-enabled=true \
  --set agent.extraArgs.file-hash-enricher-enabled=true \
  --set agent.extraArgs.signature-socks5-detection-enabled=true \
  --set agent.extraArgs.netflow-enabled=true \
  --set agent.extraArgs.netflow-export-interval=5s \
  --set agent.extraArgs.process-tree-enabled=true \
  --set agent.extraArgs.data-batch-flush-interval=1s \
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

	mu                      sync.Mutex
	containerStats          []*castaipb.ContainerStats
	nodeStats               []*castaipb.NodeStats
	containerStatsAsserterd bool
	containerEvents         []*castaipb.ContainerEvents
	eventsAsserted          bool

	logs               []*castaipb.LogEvent
	imageMetadatas     []*castaipb.ImageMetadata
	kubeBenchReports   []*castaipb.KubeBenchReport
	kubeLinterReports  []*castaipb.KubeLinterReport
	processTreeEvents  []*castaipb.ProcessTreeEvent
	controllerConfig   []byte
	agentConfig        []byte
	netflows           []*castaipb.Netflow
	netflowsAsserted   bool
	outputReceivedData bool
	nodeStatsAsserted  bool

	storageMetrics         map[string][]StorageMetricsBatch
	storageMetricsAsserted bool
}

func (t *testCASTAIServer) WriteDataBatch(ctx context.Context, req *castaipb.WriteDataBatchRequest) (*castaipb.WriteDataBatchResponse, error) {
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

	var contStats []*castaipb.ContainerStats
	for _, item := range req.Items {
		if v := item.GetContainerEvents(); v != nil {
			t.containerEvents = append(t.containerEvents, v)
		} else if v := item.GetNetflow(); v != nil {
			t.netflows = append(t.netflows, v)
		} else if v := item.GetContainerStats(); v != nil {
			contStats = append(contStats, v)
		} else if v := item.GetNodeStats(); v != nil {
			t.nodeStats = []*castaipb.NodeStats{v}
		} else if v := item.GetProcessTree(); v != nil {
			t.processTreeEvents = append(t.processTreeEvents, v)
		}
	}
	t.containerStats = contStats
	return &castaipb.WriteDataBatchResponse{}, nil
}

func (t *testCASTAIServer) WriteMetrics(stream metricspb.IngestionAPI_WriteMetricsServer) error {
	t.mu.Lock()
	if t.storageMetrics == nil {
		t.storageMetrics = make(map[string][]StorageMetricsBatch)
	}
	t.mu.Unlock()

	for {
		req, err := stream.Recv()
		if err != nil {
			break
		}

		batch := StorageMetricsBatch{
			Collection: req.Collection,
			Schema:     req.Schema,
			Metrics:    req.Metrics,
			Timestamp:  time.Now(),
		}

		if req.Metadata != nil {
			batch.Rows = req.Metadata.Rows
			batch.SkipTimestamp = req.Metadata.SkipTimestamp
		}

		t.mu.Lock()
		t.storageMetrics[req.Collection] = append(t.storageMetrics[req.Collection], batch)
		t.mu.Unlock()
	}

	return stream.SendAndClose(&metricspb.WriteMetricsResponse{Success: true})
}

func (t *testCASTAIServer) decodeBlockDeviceMetrics(schema, data []byte) ([]pipeline.BlockDeviceMetric, error) {
	avroSchema, err := avro.Parse(string(schema))
	if err != nil {
		return nil, fmt.Errorf("failed to parse schema: %w", err)
	}

	// The data contains multiple individually encoded records
	// We need to decode them one by one using a decoder
	decoder := avro.NewDecoderForSchema(avroSchema, bytes.NewReader(data))
	var results []pipeline.BlockDeviceMetric

	for {
		var metric pipeline.BlockDeviceMetric
		if err := decoder.Decode(&metric); err != nil {
			if errors.Is(err, io.EOF) {
				break // End of data
			}
			return nil, fmt.Errorf("failed to decode metric: %w", err)
		}
		results = append(results, metric)
	}

	return results, nil
}

func (t *testCASTAIServer) decodeFilesystemMetrics(schema, data []byte) ([]pipeline.FilesystemMetric, error) {
	avroSchema, err := avro.Parse(string(schema))
	if err != nil {
		return nil, fmt.Errorf("failed to parse schema: %w", err)
	}

	// The data contains multiple individually encoded records
	// We need to decode them one by one using a decoder
	decoder := avro.NewDecoderForSchema(avroSchema, bytes.NewReader(data))
	var results []pipeline.FilesystemMetric

	for {
		var metric pipeline.FilesystemMetric
		if err := decoder.Decode(&metric); err != nil {
			if errors.Is(err, io.EOF) {
				break // End of data
			}
			return nil, fmt.Errorf("failed to decode metric: %w", err)
		}
		results = append(results, metric)
	}

	return results, nil
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
			logs := slices.Clone(t.logs)
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

func (t *testCASTAIServer) assertStorageMetrics(ctx context.Context) error {
	timeout := time.After(15 * time.Second)

	expectedCollections := []string{
		"kvisor_block_device_metrics",
		"kvisor_filesystem_metrics",
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for storage metrics")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			metrics := make(map[string][]StorageMetricsBatch)
			for k, v := range t.storageMetrics {
				metrics[k] = append([]StorageMetricsBatch{}, v...)
			}
			t.mu.Unlock()

			if len(metrics) == 0 {
				continue
			}

			fmt.Printf("received storage metrics collections: %v\n", func() []string {
				var collections []string
				for collection := range metrics {
					collections = append(collections, collection)
				}
				return collections
			}())

			if batches, exists := metrics["kvisor_block_device_metrics"]; exists {
				for _, batch := range batches {
					blockMetrics, err := t.decodeBlockDeviceMetrics(batch.Schema, batch.Metrics)
					if err != nil {
						return fmt.Errorf("failed to decode block device metrics: %w", err)
					}

					for _, metric := range blockMetrics {
						if metric.Name == "" {
							return errors.New("block device metric missing name")
						}
						if metric.NodeName == "" {
							return errors.New("block device metric missing node name")
						}
						if len(metric.PhysicalDevices) == 0 {
							return errors.New("block device metric missing physical devices")
						}

						if metric.Size != nil && *metric.Size < 0 {
							return fmt.Errorf("block device metric has negative size: %d", metric.ReadIOPS)
						}

						if metric.ReadIOPS < 0 {
							return fmt.Errorf("block device metric has negative read IOPS: %d", metric.ReadIOPS)
						}
						if metric.WriteIOPS < 0 {
							return fmt.Errorf("block device metric has negative write IOPS: %d", metric.WriteIOPS)
						}

						if metric.ReadThroughput < 0 {
							return fmt.Errorf("block device metric has negative ReadThroughput: %d", metric.ReadIOPS)
						}

						if metric.WriteThroughput < 0 {
							return fmt.Errorf("block device metric has negative WriteThroughput: %d", metric.WriteIOPS)
						}
					}
				}
			}

			if batches, exists := metrics["kvisor_filesystem_metrics"]; exists {
				for _, batch := range batches {
					fsMetrics, err := t.decodeFilesystemMetrics(batch.Schema, batch.Metrics)
					if err != nil {
						return fmt.Errorf("failed to decode filesystem metrics: %w", err)
					}

					for _, metric := range fsMetrics {
						if metric.NodeName == "" {
							return errors.New("filesystem metric missing node name")
						}
						if metric.MountPoint == "" {
							return errors.New("filesystem metric missing mount point")
						}
						if len(metric.Devices) == 0 {
							return errors.New("filesystem metric missing devices")
						}
						if metric.TotalSize == nil {
							return errors.New("filesystem metric missing total size")
						}
						if metric.UsedSpace == nil {
							return errors.New("filesystem metric missing used space")
						}
					}
				}
			}

			foundCollections := 0
			for _, expectedCollection := range expectedCollections {
				if _, exists := metrics[expectedCollection]; exists {
					foundCollections++
				}
			}

			if foundCollections == len(expectedCollections) {
				fmt.Printf("all storage metrics collections received and validated\n")
				return nil
			}
		}
	}
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
				r.NotEmpty(batch.ImageDigest)

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

				for _, e := range batch.Items {
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

				for _, e := range batch.Items {
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
			for _, batch := range t.containerEvents {
				if err := validator.validate(validator, batch); err != nil {
					errs = append(errs, err)
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

	r := newAssertions()
	var resourceUsageStatsFound bool
	var fileAccessInUsrDirFound bool
	var fileAccessInTruncatedDirFound bool

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf(
				"timeout waiting for received container stats, resource_usage_stats=%v, file_access_usr_dir=%v, file_access_trunc_dir=%v",
				resourceUsageStatsFound,
				fileAccessInUsrDirFound,
				fileAccessInTruncatedDirFound,
			)
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			stats := slices.Clone(t.containerStats)
			t.mu.Unlock()
			if len(stats) == 0 {
				continue
			}
			fmt.Printf("asserting container stats, items=%d\n", len(stats))

			for _, cont := range stats {
				r.NotEmpty(cont.Namespace)
				r.NotEmpty(cont.PodName)
				r.NotEmpty(cont.ContainerName)
				r.NotEmpty(cont.NodeName)

				var cpuUsage, memUsage uint64
				if cont.CpuStats != nil {
					cpuUsage = cont.CpuStats.TotalUsage
				}
				if cont.MemoryStats != nil {
					memUsage = cont.MemoryStats.Usage.Usage
				}
				if cpuUsage > 0 && memUsage > 0 {
					resourceUsageStatsFound = true
				}

				if cont.FilesAccessStats != nil {
					for _, f := range cont.FilesAccessStats.Paths {
						r.NotEmpty(f)
						if strings.HasPrefix(f, "/usr/bin/iperf") {
							fileAccessInUsrDirFound = true
						} else if strings.HasPrefix(f, "/proc/*") {
							fileAccessInTruncatedDirFound = true
						}
					}
					for _, reads := range cont.FilesAccessStats.Reads {
						r.NotEmpty(reads)
					}
				}
			}

			if resourceUsageStatsFound && fileAccessInUsrDirFound && fileAccessInTruncatedDirFound {
				return r.error()
			}
		}
	}
}

func (t *testCASTAIServer) assertNodeStats(ctx context.Context) error {
	timeout := time.After(10 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for received node stats")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			stats := slices.Clone(t.nodeStats)
			t.mu.Unlock()
			if len(stats) == 0 {
				continue
			}

			for _, cont := range stats {
				if cont.NodeName == "" {
					return fmt.Errorf("missing node: %+v", cont)
				}
				cpuUsage := cont.CpuStats.TotalUsage
				memUsage := cont.MemoryStats.Usage.Usage
				if cpuUsage == 0 && memUsage == 0 {
					return errors.New("missing cpu or memory usage")
				}
				t.nodeStatsAsserted = true
			}
			return nil
		}
	}
}

type resourceUsage struct {
	cpu        uint64
	mem        uint64
	cpuHistory []uint64
	memHistory []uint64

	maxExpectedCPU uint64
	maxExpectedMem uint64
}

func (r *resourceUsage) update(st *castaipb.ContainerStats) {
	r.cpuHistory = append(r.cpuHistory, st.CpuStats.TotalUsage)
	if curr := st.CpuStats.TotalUsage; curr > r.cpu {
		r.cpu = curr
	}
	r.memHistory = append(r.memHistory, st.MemoryStats.Usage.Usage)
	if curr := st.MemoryStats.Usage.Usage; curr > r.cpu {
		r.mem = curr
	}
}

func (t *testCASTAIServer) assertKvisorResourceUsage(ctx context.Context) error {
	timeout := time.After(10 * time.Second)

	resourceUsages := map[string]*resourceUsage{
		"agent": {
			maxExpectedCPU: 600_000_000,       // 600m.
			maxExpectedMem: 256 * 1024 * 1024, // 256Mi
		},
		"controller": {
			maxExpectedCPU: 600_000_000,       // 600m.
			maxExpectedMem: 128 * 1024 * 1024, // 256Mi.
		},
	}
	checkResourceUsage := func(stats []*castaipb.ContainerStats) (bool, error) {
		agent := resourceUsages["agent"]
		controller := resourceUsages["controller"]
		for _, st := range stats {
			if st.Namespace == "kvisor-e2e" {
				if strings.Contains(st.PodName, "kvisor-agent") {
					agent.update(st)
				} else if strings.Contains(st.PodName, "kvisor-controller") {
					controller.update(st)
				}
			}
		}

		if len(agent.cpuHistory) >= 5 && len(controller.cpuHistory) >= 5 {
			var errs []error
			if agent.cpu > agent.maxExpectedCPU {
				errs = append(errs, fmt.Errorf("agent: expected cpu max %d, got %d, history: %v", agent.maxExpectedCPU, agent.cpu, agent.cpuHistory))
			}
			if agent.mem > agent.maxExpectedMem {
				errs = append(errs, fmt.Errorf("agent: expected mem max %d, got %d, history: %v", agent.maxExpectedMem, agent.mem, agent.memHistory))
			}
			if controller.cpu > controller.maxExpectedCPU {
				errs = append(errs, fmt.Errorf("controller: expected cpu max %d, got %d, history: %v", controller.maxExpectedCPU, controller.cpu, controller.cpuHistory))
			}
			if controller.mem > controller.maxExpectedMem {
				errs = append(errs, fmt.Errorf("controller: expected mem max %d, got %d, history: %v", controller.maxExpectedMem, controller.mem, controller.memHistory))
			}
			if len(errs) > 0 {
				return false, errors.Join(errs...)
			}
			return true, nil
		}
		return false, nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for kvisor components resource usage")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			stats := slices.Clone(t.containerStats)
			t.mu.Unlock()
			if len(stats) == 0 {
				continue
			}

			ok, err := checkResourceUsage(stats)
			if err != nil {
				return err
			}
			if ok {
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
			items := slices.Clone(t.netflows)
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

func (t *testCASTAIServer) assertIperfNetflows(ctx context.Context) error {
	timeout := time.After(30 * time.Second)
	r := newAssertions()

	var foundClient, foundServer bool

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting for iperf netflows")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			items := slices.Clone(t.netflows)
			t.mu.Unlock()

			for _, f1 := range items {
				if f1.WorkloadKind == "DaemonSet" && f1.WorkloadName == "iperf-clients" {
					r.Equal("iperf", f1.Namespace)
					r.Equal("iperf-client", f1.ContainerName)
					r.Equal("iperf", f1.ProcessName)
					r.NotEmpty(f1.Pid)
					r.NotEmpty(f1.ProcessStartTime)
					for _, d1 := range f1.Destinations {
						if d1.WorkloadName == "iperf-server" {
							r.Equal("iperf-server.kvisor-e2e.svc.cluster.local", d1.DnsQuestion)
							r.Greater(d1.TxBytes, d1.RxBytes)
							r.GreaterOrEqual(d1.TxBytes, 256*1024)
							r.LessOrEqual(d1.TxBytes, 1*1024*1024)
							foundClient = true
						}
					}
				}

				if f1.WorkloadKind == "Deployment" && f1.WorkloadName == "iperf-server" {
					r.Equal("iperf", f1.Namespace)
					r.Equal("iperf-server", f1.ContainerName)
					r.Equal("iperf", f1.ProcessName)
					r.NotEmpty(f1.Pid)
					r.NotEmpty(f1.ProcessStartTime)
					for _, d1 := range f1.Destinations {
						if d1.WorkloadName == "iperf-client" {
							r.Greater(d1.RxBytes, d1.TxBytes)
							r.GreaterOrEqual(d1.RxBytes, 256*1024)
						}
						foundServer = true
					}
				}
			}

			if foundClient && foundServer {
				return r.error()
			}
		}
	}
}

func (t *testCASTAIServer) assertProcessTree(ctx context.Context) error {
	timeout := time.After(10 * time.Second)

	r := newAssertions()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return errors.New("timeout waiting initial process tree")
		case <-time.After(1 * time.Second):
			t.mu.Lock()
			ptree := slices.Clone(t.processTreeEvents)
			t.mu.Unlock()

			if len(ptree) > 0 {
				l1 := ptree[0]
				r.NotEmpty(l1.Events)
				e1 := l1.Events[0]
				r.NotEmpty(e1.Timestamp)
				r.NotEmpty(e1.Process.Pid)
				r.NotEmpty(e1.Process.Filepath)
				r.NotEmpty(e1.Process.Ppid)
				r.NotEmpty(e1.Process.StartTime)

				return r.error()
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
