package admissionpolicy

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	memory "k8s.io/client-go/discovery/cached"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

//go:embed policies
var policyFS embed.FS

// EnsurePolicies ensures that all policies are present in the cluster.
func EnsurePolicies(ctx context.Context, cfg *rest.Config) error {
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
	return fs.WalkDir(policyFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := policyFS.ReadFile(path)
		if err != nil {
			return err
		}
		obj := &unstructured.Unstructured{}
		_, gvk, err := decoder.Decode(data, nil, obj)
		if err != nil {
			return err
		}
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return err
		}
		data, err = json.Marshal(obj)
		if err != nil {
			return err
		}
		_, err = dyn.Resource(mapping.Resource).Patch(ctx, obj.GetName(), types.ApplyPatchType, data, metav1.PatchOptions{
			FieldManager: "sample-controller",
			Force:        &[]bool{true}[0],
		})
		return err
	})
}
