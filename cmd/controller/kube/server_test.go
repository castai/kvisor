package kube

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	kubepb "github.com/castai/kvisor/api/v1/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
)

func TestServer(t *testing.T) {
	ctx := context.Background()
	log := logging.NewTestLog()

	clientset := fake.NewClientset()
	client := NewClient(log, "castai-kvisor", "kvisor", Version{}, clientset)
	client.index = NewIndex()

	client.index.nodesByName["n1"] = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"topology.kubernetes.io/zone": "us-east-1a",
			},
		},
		Spec: corev1.NodeSpec{
			PodCIDR:  "10.10.10.0/24",
			PodCIDRs: []string{"10.10.10.0/24", "fd00::/64"},
		},
	}

	client.index.pods["p1"] = &PodInfo{
		Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				UID:  "p1",
				Name: "p1",
				OwnerReferences: []metav1.OwnerReference{
					{
						UID:  "st1",
						Kind: "StatefulSet",
						Name: "st1",
					},
				},
			},
			Spec: corev1.PodSpec{
				NodeName: "n1",
			},
			Status: corev1.PodStatus{
				PodIP: "10.10.10.10",
				PodIPs: []corev1.PodIP{
					{
						IP: "10.10.10.10",
					},
					{
						IP: "fd00::1",
					},
				},
			},
		},
		Owner: metav1.OwnerReference{
			UID:  "st1",
			Kind: "StatefulSet",
			Name: "st1-name",
		},
		Zone: "us-east-1a",
	}
	client.index.ipsDetails[netip.MustParseAddr("10.10.10.10")] = IPInfo{
		IP:      "",
		PodInfo: client.index.pods["p1"],
		Node:    client.index.nodesByName["n1"],
	}
	client.index.ipsDetails[netip.MustParseAddr("fd00::1")] = IPInfo{
		IP:      "",
		PodInfo: client.index.pods["p1"],
		Node:    client.index.nodesByName["n1"],
	}
	clientset.PrependReactor("create", "services", func(action kubetesting.Action) (bool, runtime.Object, error) {
		svc := action.(kubetesting.CreateAction).GetObject().(*corev1.Service)
		switch svc.Spec.ClusterIP {
		case "0.0.0.0":
			return true, svc, fmt.Errorf("The range of valid IPs is 10.30.0.0/16")
		case "::":
			return true, svc, fmt.Errorf("The range of valid IPs is fd01::/48")
		}
		return false, nil, nil
	})

	srv := NewServer(client)

	t.Run("get pod by id", func(t *testing.T) {
		r := require.New(t)
		resp, err := srv.GetPod(ctx, &kubepb.GetPodRequest{
			Uid: "p1",
		})
		r.NoError(err)
		r.Equal("st1", resp.Pod.WorkloadUid)
		r.Equal("st1-name", resp.Pod.WorkloadName)
		r.Equal("StatefulSet", resp.Pod.WorkloadKind)
		r.Equal("us-east-1a", resp.Pod.Zone)
		r.Equal("n1", resp.Pod.NodeName)
	})

	t.Run("pod not found", func(t *testing.T) {
		r := require.New(t)
		_, err := srv.GetPod(ctx, &kubepb.GetPodRequest{
			Uid: "p2",
		})
		st, _ := status.FromError(err)
		r.Equal(codes.NotFound, st.Code())
	})

	t.Run("get ipv4 info", func(t *testing.T) {
		r := require.New(t)
		resp, err := srv.GetIPInfo(ctx, &kubepb.GetIPInfoRequest{
			Ip: netip.MustParseAddr("10.10.10.10").AsSlice(),
		})
		r.NoError(err)
		r.Equal("p1", resp.Info.PodName)
		r.Equal("st1-name", resp.Info.WorkloadName)
		r.Equal("StatefulSet", resp.Info.WorkloadKind)
		r.Equal("us-east-1a", resp.Info.Zone)
		r.Equal("n1", resp.Info.NodeName)
	})

	t.Run("get ipv6 info", func(t *testing.T) {
		r := require.New(t)
		resp, err := srv.GetIPInfo(ctx, &kubepb.GetIPInfoRequest{
			Ip: netip.MustParseAddr("fd00::1").AsSlice(),
		})
		r.NoError(err)
		r.Equal("p1", resp.Info.PodName)
		r.Equal("st1-name", resp.Info.WorkloadName)
		r.Equal("StatefulSet", resp.Info.WorkloadKind)
		r.Equal("us-east-1a", resp.Info.Zone)
		r.Equal("n1", resp.Info.NodeName)
	})

	t.Run("get ip info not found", func(t *testing.T) {
		r := require.New(t)
		_, err := srv.GetIPInfo(ctx, &kubepb.GetIPInfoRequest{
			Ip: netip.MustParseAddr("10.2.2.2").AsSlice(),
		})
		st, _ := status.FromError(err)
		r.Equal(codes.NotFound, st.Code())
	})

	t.Run("get cluster info", func(t *testing.T) {
		r := require.New(t)
		resp, err := srv.GetClusterInfo(ctx, &kubepb.GetClusterInfoRequest{})
		r.NoError(err)
		r.ElementsMatch([]string{"10.10.10.0/24", "fd00::/64"}, resp.PodsCidr)
		r.ElementsMatch([]string{"10.30.0.0/16", "fd01::/48"}, resp.ServiceCidr)
	})
}
