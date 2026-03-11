package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/castai/logging"
)

// dcgmExporterImages are the known DCGM exporter container image prefixes to match against.
var dcgmExporterImages = []string{
	"nvcr.io/nvidia/k8s/dcgm-exporter",
	"nvidia/dcgm-exporter",
	"nvidia/gke-dcgm-exporter",
}

const dcgmExporterCommandSubstring = "dcgm-exporter"

// discoveryResult holds the outcome of the cluster scan.
type discoveryResult struct {
	// DCGMExists is true if an existing DCGM exporter DaemonSet was found.
	DCGMExists bool
	// DCGMSelector is the label selector (e.g. "app.kubernetes.io/name=dcgm-exporter")
	// that identifies the DCGM exporter pods. Empty when DCGMExists is false.
	DCGMSelector string
}

// NewFeatureDiscoveryCommand returns the cobra command for the feature-discovery subcommand.
// It is run as a Kubernetes init container and writes discovery results to a shared emptyDir.
func NewFeatureDiscoveryCommand() *cobra.Command {
	var (
		outputDir         string
		selfDaemonSetName string
		selfNamespace     string
	)

	command := &cobra.Command{
		Use:   "feature-discovery",
		Short: "Discover GPU-related components in the cluster and write results to a shared volume",
		Run: func(cmd *cobra.Command, args []string) {
			log := logging.New()

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			if err := runFeatureDiscovery(ctx, log, outputDir, selfDaemonSetName, selfNamespace); err != nil {
				log.Errorf("feature discovery failed: %v", err)
				// Non-fatal: write safe defaults and exit 0 so the pod can still start.
				writeDefaults(log, outputDir)
			}
		},
	}

	command.Flags().StringVar(&outputDir, "output-dir", "/shared", "Directory to write discovery result files")
	command.Flags().StringVar(&selfDaemonSetName, "self-daemonset-name", "", "Name of kvisor's own DaemonSet to skip during discovery")
	command.Flags().StringVar(&selfNamespace, "self-namespace", "", "Namespace of kvisor's own DaemonSet")

	return command
}

func runFeatureDiscovery(ctx context.Context, log *logging.Logger, outputDir, selfDaemonSetName, selfNamespace string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("creating output dir %s: %w", outputDir, err)
	}

	k8sCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("getting in-cluster config: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(k8sCfg)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	result, err := discoverDCGM(ctx, log, k8sClient, selfDaemonSetName, selfNamespace)
	if err != nil {
		return fmt.Errorf("scanning cluster for dcgm-exporter: %w", err)
	}

	if result.DCGMExists {
		log.Infof("discovered existing dcgm-exporter (selector=%q), kvisor will scrape it", result.DCGMSelector)
	} else {
		log.Info("no existing dcgm-exporter found, kvisor sidecar will start its own")
	}

	return writeResult(log, outputDir, result)
}

// discoverDCGM scans all DaemonSets cluster-wide for an existing DCGM exporter.
func discoverDCGM(ctx context.Context, log *logging.Logger, client kubernetes.Interface, selfDSName, selfNS string) (discoveryResult, error) {
	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return discoveryResult{}, fmt.Errorf("listing namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		dsList, err := client.AppsV1().DaemonSets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Warnf("listing daemonsets in namespace %s: %v", ns.Name, err)
			continue
		}

		for _, ds := range dsList.Items {
			// Skip kvisor's own DaemonSet to avoid self-detection.
			if selfDSName != "" && ds.Name == selfDSName && ds.Namespace == selfNS {
				continue
			}

			if isDCGMExporter(ds) {
				selector := extractDCGMSelector(ds)
				return discoveryResult{DCGMExists: true, DCGMSelector: selector}, nil
			}
		}
	}

	return discoveryResult{DCGMExists: false}, nil
}

// isDCGMExporter returns true if the DaemonSet is running dcgm-exporter,
// detected via container image, command, or args (in that order).
func isDCGMExporter(ds appsv1.DaemonSet) bool {
	for _, c := range ds.Spec.Template.Spec.Containers {
		// 1. Image check.
		for _, knownImage := range dcgmExporterImages {
			if strings.Contains(c.Image, knownImage) {
				return true
			}
		}
		// 2. Command check.
		for _, cmd := range c.Command {
			if strings.Contains(cmd, dcgmExporterCommandSubstring) {
				return true
			}
		}
		// 3. Args check (covers /bin/bash -c "dcgm-exporter ..." pattern).
		for _, arg := range c.Args {
			if strings.Contains(arg, dcgmExporterCommandSubstring) {
				return true
			}
		}
	}
	return false
}

// extractDCGMSelector derives a pod label selector from the DaemonSet's matchLabels or metadata labels.
// Priority: app.kubernetes.io/name from matchLabels, then metadata labels, then "app" label.
func extractDCGMSelector(ds appsv1.DaemonSet) string {
	// Prefer spec.selector.matchLabels (most reliable for pod targeting).
	if ds.Spec.Selector != nil {
		if v, ok := ds.Spec.Selector.MatchLabels["app.kubernetes.io/name"]; ok && v != "" {
			return fmt.Sprintf("app.kubernetes.io/name=%s", v)
		}
		if v, ok := ds.Spec.Selector.MatchLabels["app"]; ok && v != "" {
			return fmt.Sprintf("app=%s", v)
		}
	}
	// Fall back to DaemonSet metadata labels.
	if v, ok := ds.Labels["app.kubernetes.io/name"]; ok && v != "" {
		return fmt.Sprintf("app.kubernetes.io/name=%s", v)
	}
	if v, ok := ds.Labels["app"]; ok && v != "" {
		return fmt.Sprintf("app=%s", v)
	}
	return ""
}

func writeResult(log *logging.Logger, outputDir string, result discoveryResult) error {
	dcgmExistsVal := "false"
	if result.DCGMExists {
		dcgmExistsVal = "true"
	}

	if err := writeFile(filepath.Join(outputDir, "dcgm-exists"), dcgmExistsVal); err != nil {
		return fmt.Errorf("writing dcgm-exists: %w", err)
	}
	log.Infof("wrote %s/dcgm-exists = %s", outputDir, dcgmExistsVal)

	if err := writeFile(filepath.Join(outputDir, "dcgm-selector"), result.DCGMSelector); err != nil {
		return fmt.Errorf("writing dcgm-selector: %w", err)
	}
	if result.DCGMSelector != "" {
		log.Infof("wrote %s/dcgm-selector = %s", outputDir, result.DCGMSelector)
	}

	return nil
}

// writeDefaults writes safe fallback values so the pod can start even if discovery errored.
func writeDefaults(log *logging.Logger, outputDir string) {
	_ = os.MkdirAll(outputDir, 0o755)
	if err := writeFile(filepath.Join(outputDir, "dcgm-exists"), "false"); err != nil {
		log.Warnf("writing default dcgm-exists: %v", err)
	}
	if err := writeFile(filepath.Join(outputDir, "dcgm-selector"), ""); err != nil {
		log.Warnf("writing default dcgm-selector: %v", err)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644) //nolint:gosec
}
