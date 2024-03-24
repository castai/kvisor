package admissionpolicy

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestValidator(t *testing.T) {
	_ = setupEnvTest(t)
}

func setupEnvTest(t *testing.T) *Validator {
	// t.Helper()
	ctx := context.Background()
	scheme := runtime.NewScheme()
	clientgoscheme.AddToScheme(scheme)
	env := &envtest.Environment{
		Scheme: scheme,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	t.Cleanup(func() {
		err := env.Stop()
		if err != nil {
			t.Log("error stopping envtest environment:", err)
		}
	})
	err = EnsurePolicies(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go validator.Run(stop)
	for !validator.HasSynced() {
		time.Sleep(time.Second)
	}
	t.Cleanup(func() {
		close(stop)
	})
	return validator
}
