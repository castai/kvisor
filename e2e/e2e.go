package main

import (
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/castai/kvisor/castai"
	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeconfig = flag.String("kubeconfig", "", "Path to kubeconfig. If not set in cluster config will be used.")
	imageTag   = flag.String("image-tag", "", "Kvisor docker image tag")
	timeout    = flag.Duration("timeout", 2*time.Minute, "Test timeout")
)

const (
	ns = "castai-kvisor-e2e"
)

func main() {
	flag.Parse()
	log := logrus.New()
	if err := run(log); err != nil {
		log.Fatal(err)
	}
}

func run(log logrus.FieldLogger) error {
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if *imageTag == "" {
		return errors.New("image-tag flag is not set")
	}

	api := &mockAPI{log: log, receivedEvents: map[string][][]byte{}}
	go api.start()

	out, err := installChart(ns, *imageTag)
	if err != nil {
		return fmt.Errorf("installing chart: %w: %s", err, string(out))
	}
	fmt.Printf("installed chart:\n%s\n", out)

	restconfig, err := getKubeConfig(*kubeconfig)
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(restconfig)
	if err != nil {
		return err
	}
	if err := assertJobsCompleted(ctx, client, "imgscan"); err != nil {
		return fmt.Errorf("image scan jobs assert: %w", err)
	}
	// TODO: Kube-bench jobs are not working.
	//if err := assertJobsCompleted(ctx, client, "kube-bench"); err != nil {
	//	return fmt.Errorf("kube bench jobs assert: %w", err)
	//}
	if err := api.assertChecksReceived(castai.ReportTypeDelta); err != nil {
		return err
	}
	// TODO: Assert collected api requests.
	return nil
}

func assertJobsCompleted(ctx context.Context, client kubernetes.Interface, jobPrefix string) error {
	errWaitingCompletion := errors.New("jobs not completed yet")
	assert := func() error {
		selector := labels.Set{"app.kubernetes.io/managed-by": "castai"}.String()
		jobs, err := client.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{
			LabelSelector: selector,
		})
		if err != nil {
			return err
		}

		filteredJobs := lo.Filter(jobs.Items, func(v batchv1.Job, _ int) bool {
			return strings.HasPrefix(v.Name, jobPrefix)
		})

		var finished bool
		fmt.Printf("found %d jobs for prefix %q\n", len(filteredJobs), jobPrefix)
		for _, job := range filteredJobs {
			fmt.Printf("name=%s, succeeded=%d, active=%d, failed=%d\n", job.Name, job.Status.Succeeded, job.Status.Active, job.Status.Failed)
			if job.Status.Failed > 0 {
				logs, err := getJobPodLogs(ctx, client, job.Name)
				if err != nil {
					return fmt.Errorf("reading failed jobs logs: %w", err)
				}
				return fmt.Errorf("job %s failed, logs=%s", job.Name, string(logs))
			}
			if job.Status.Succeeded > 0 {
				finished = true
			}
		}
		if finished {
			return nil
		}

		return errWaitingCompletion
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
			err := assert()
			if err == nil {
				return nil
			}
			if !errors.Is(err, errWaitingCompletion) {
				return err
			}
		}
	}
}

func installChart(ns, imageTag string) ([]byte, error) {
	podIP := os.Getenv("POD_IP")
	apiURL := fmt.Sprintf("http://%s:8090", podIP)
	//nolint:gosec
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf(`helm upgrade --install castai-kvisor ./charts/castai-kvisor \
  -n %s --create-namespace \
  -f ./charts/castai-kvisor/ci/test-values.yaml \
  --set image.repository=ghcr.io/castai/kvisor/kvisor,image.tag=%s \
  --set-string structuredConfig.imageScan.image.name=ghcr.io/castai/kvisor/kvisor-imgcollector:%s \
  --set castai.apiURL=%s \
  --wait --timeout=1m`, ns, imageTag, imageTag, apiURL))
	return cmd.CombinedOutput()
}

type mockAPI struct {
	log logrus.FieldLogger

	mu             sync.Mutex
	receivedLogs   []string
	receivedEvents map[string][][]byte
}

func (m *mockAPI) start() {
	router := mux.NewRouter()

	router.HandleFunc("/v1/security/insights/agent/{cluster_id}/{event}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clusterID := vars["cluster_id"]
		event := vars["event"]
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			m.log.Errorf("gzip reader: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer gz.Close()

		rawBody, err := io.ReadAll(gz)
		if err != nil {
			m.log.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Printf("received event=%s, cluster_id=%s, body=%d\n", event, clusterID, len(rawBody))
		m.mu.Lock()
		m.receivedEvents[event] = append(m.receivedEvents[event], rawBody)
		m.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})

	router.HandleFunc("/v1/security/insights/{cluster_id}/log", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clusterID := vars["cluster_id"]
		body, err := io.ReadAll(r.Body)
		if err != nil {
			m.log.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		m.mu.Lock()
		m.receivedLogs = append(m.receivedLogs, string(body))
		m.mu.Unlock()
		fmt.Printf("received log, cluster_id=%s, body=%d\n", clusterID, len(body))
		w.WriteHeader(http.StatusOK)
	})

	if err := http.ListenAndServe(":8090", router); err != nil { //nolint:gosec
		m.log.Fatal(err)
	}
}

func (m *mockAPI) assertChecksReceived(reportType string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	payloads, ok := m.receivedEvents[reportType]
	if !ok {
		return fmt.Errorf("no received events for %q type", reportType)
	}
	payload := payloads[0]

	switch reportType {
	case castai.ReportTypeLinter:
		var checks []castai.LinterCheck
		if err := jsoniter.Unmarshal(payload, &checks); err != nil {
			return err
		}
		if !lo.EveryBy(checks, func(v castai.LinterCheck) bool { return v.ResourceID != "" }) {
			return errors.New("not all checks contains resource id")
		}
		if !lo.SomeBy(checks, func(v castai.LinterCheck) bool { return len(v.Failed.Rules()) > 0 }) {
			return errors.New("no failed checks found")
		}
		if !lo.SomeBy(checks, func(v castai.LinterCheck) bool { return len(v.Passed.Rules()) > 0 }) {
			return errors.New("no passed checks found")
		}
		return nil
	default:
		return fmt.Errorf("not asserted report type %q", reportType)
	}
}

func getKubeConfig(kubepath string) (*rest.Config, error) {
	if kubepath != "" {
		data, err := os.ReadFile(kubepath)
		if err != nil {
			return nil, fmt.Errorf("reading kubeconfig at %s: %w", kubepath, err)
		}
		restConfig, err := clientcmd.RESTConfigFromKubeConfig(data)
		if err != nil {
			return nil, fmt.Errorf("building rest config from kubeconfig at %s: %w", kubepath, err)
		}
		return restConfig, nil
	}

	return rest.InClusterConfig()
}

func getJobPodLogs(ctx context.Context, client kubernetes.Interface, jobName string) ([]byte, error) {
	jobPods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{"job-name": jobName}.String()})
	if err != nil {
		return nil, err
	}
	if len(jobPods.Items) == 0 {
		return nil, errors.New("job pod not found")
	}
	jobPod := jobPods.Items[0]
	logsStream, err := client.CoreV1().Pods(ns).GetLogs(jobPod.Name, &corev1.PodLogOptions{}).Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating logs stream: %w", err)
	}
	defer logsStream.Close()
	logs, err := io.ReadAll(logsStream)
	if err != nil {
		return nil, fmt.Errorf("reading logs: %w", err)
	}
	return logs, nil
}
