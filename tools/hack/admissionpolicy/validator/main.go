package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/castai/kvisor/pkg/admissionpolicy"
)

func main() {
	ctx := context.Background()
	home := os.Getenv("HOME")
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}
	defaultKubeconfig := home + "/.kube/config"
	kubeconfig := flag.String("kubeconfig", defaultKubeconfig, "Path to a kubeconfig. Only required if out-of-cluster.")
	cfg, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err)
	}
	cfg.QPS = 100
	cfg.Burst = 100

	// Ensure policies in cluster
	err = admissionpolicy.EnsurePolicies(ctx, cfg)
	if err != nil {
		panic(err)
	}

	// Setup and start the validator
	validator, err := admissionpolicy.NewValidator(cfg)
	if err != nil {
		panic(err)
	}
	stop := make(chan struct{})
	log.Println("Starting policy evaluator and informer caches")
	go validator.Run(stop)

	// Wait for ready
	timeout := 10 * time.Second
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

WaitForReady:
	for {
		select {
		case <-waitCtx.Done():
			log.Fatalf("Timed out waiting for validator to become ready")
		default:
			if validator.HasSynced() {
				break WaitForReady
			}
		}
	}

	// List all resources in the cluster
	resources, err := collectServerResources(ctx, cfg)
	if err != nil {
		panic(err)
	}

	// Validate all resources
	for gvr, list := range resources {
		for _, obj := range list.Items {
			resource := fmt.Sprintf("%s/%s", gvr.Resource, gvr.GroupVersion().String())
			log.Printf("Validating %s/%s", resource, obj.GetName())
			err := validator.Validate(ctx, &obj)
			if err != nil {
				log.Printf("   Failed: %v", err)
			} else {
				log.Println("   Passed")
			}
		}
	}

	// Stop the validator
	close(stop)
}

func collectServerResources(ctx context.Context, cfg *rest.Config) (map[schema.GroupVersionResource]*unstructured.UnstructuredList, error) {
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	discovery := clientset.Discovery()
	groups, err := discovery.ServerPreferredResources()
	if err != nil {
		return nil, err
	}
	resmu := sync.Mutex{}
	results := make(map[schema.GroupVersionResource]*unstructured.UnstructuredList)
	var wg sync.WaitGroup
	for _, group := range groups {
		if group.GroupVersion == "authorization.k8s.io/v1" || group.GroupVersion == "authentication.k8s.io/v1" {
			// Skip auth groups
			continue
		}
		wg.Add(1)
		go func(group *metav1.APIResourceList) {
			defer wg.Done()
			for _, resource := range group.APIResources {
				if strings.Contains(resource.Name, "/") {
					// Skip subresources
					continue
				}
				gvr := schema.GroupVersionResource{
					Group:    group.GroupVersion,
					Version:  resource.Version,
					Resource: resource.Name,
				}
				if gvr.Group == "v1" {
					gvr.Version = gvr.Group
					gvr.Group = ""
				}
				if gvr.Version == "v1" && (gvr.Resource == "events" || gvr.Resource == "bindings") {
					// Skip events and bindings
					continue
				}
				var list *unstructured.UnstructuredList
				if resource.Namespaced {
					list, err = dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
				} else {
					list, err = dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
				}
				if err != nil {
					log.Printf("Failed to list %s: %v", gvr, err)
					continue
				}
				resmu.Lock()
				results[gvr] = list
				resmu.Unlock()
			}
		}(group)
	}
	wg.Wait()
	return results, nil
}
