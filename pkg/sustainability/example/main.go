package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/sustainability"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	// Create Kubernetes client
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		log.Fatalf("Failed to build kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Create informer factory
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)

	// Create logger
	logger := logging.New(&logging.Config{
		Level: logging.MustParseLevel("info"),
	})

	// Create sustainability controller
	sustainabilityController, err := sustainability.NewController(
		logger,
		clientset,
		informerFactory,
		prometheus.DefaultRegisterer,
		"", // Use default config path
	)
	if err != nil {
		log.Fatalf("Failed to create sustainability controller: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start informer factory
	informerFactory.Start(ctx.Done())
	informerFactory.WaitForCacheSync(ctx.Done())

	// Start sustainability controller
	if err := sustainabilityController.Start(ctx); err != nil {
		log.Fatalf("Failed to start sustainability controller: %v", err)
	}

	// Print initial config
	sustainabilityConfig := sustainabilityController.GetConfig()
	fmt.Printf("Sustainability controller started with config:\n")
	fmt.Printf("  Carbon Intensity: %.2f gCO2e/kWh\n", sustainabilityConfig.CarbonIntensityGCO2PerKWh)
	fmt.Printf("  Energy Price: %.4f USD/kWh\n", sustainabilityConfig.EnergyPriceUSDPerKWh)
	fmt.Printf("  Scrape Interval: %d seconds\n", sustainabilityConfig.ScrapeIntervalSeconds)
	fmt.Printf("  Worker Count: %d\n", sustainabilityConfig.WorkerCount)

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Sustainability controller is running. Press Ctrl+C to stop.")

	// Example of monitoring aggregations
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				printAggregationStats(sustainabilityController)
			}
		}
	}()

	<-sigChan
	fmt.Println("\nShutting down sustainability controller...")
	sustainabilityController.Stop()
}

func printAggregationStats(controller *sustainability.Controller) {
	aggregator := controller.GetAggregator()
	seriesCount, nsCount, workloadCount := aggregator.GetStats()

	fmt.Printf("[%s] Aggregation stats: %d series, %d namespaces, %d workloads\n",
		time.Now().Format("15:04:05"), seriesCount, nsCount, workloadCount)

	// Print namespace aggregations
	nsAggregates := aggregator.GetNamespaceAggregations()
	if len(nsAggregates) > 0 {
		fmt.Printf("  Namespace energy consumption:\n")
		for key, joules := range nsAggregates {
			kwh := sustainability.ConvertJoulesToKWh(joules)
			fmt.Printf("    %s: %.3f kWh (%.0f J)\n", key.Namespace, kwh, joules)
		}
	}

	// Print workload aggregations
	workloadAggregates := aggregator.GetWorkloadAggregations()
	if len(workloadAggregates) > 0 {
		fmt.Printf("  Workload energy consumption:\n")
		for key, joules := range workloadAggregates {
			kwh := sustainability.ConvertJoulesToKWh(joules)
			fmt.Printf("    %s/%s (%s): %.3f kWh (%.0f J)\n",
				key.Namespace, key.WorkloadName, key.WorkloadType, kwh, joules)
		}
	}
}
