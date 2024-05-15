package state

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestClickhouseNetflowExporter(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	r := require.New(t)
	ctx := context.Background()
	log := logging.NewTestLog()

	addr, cleanup := startClickhouseDB(t)
	defer cleanup()

	conn, err := newClickhouseConn(addr)
	r.NoError(err)

	r.NoError(conn.Exec(ctx, ClickhouseNetflowSchema()))

	exporter := NewClickhouseNetflowExporter(log, conn, 100)
	err = exporter.asyncWrite(ctx, true, &castpb.Netflow{
		StartTs:       uint64(time.Now().UnixNano()),
		EndTs:         uint64(time.Now().Add(time.Minute).UnixNano()),
		ProcessName:   "curl",
		Namespace:     "n1",
		PodName:       "p1",
		ContainerName: "c1",
		WorkloadName:  "w1",
		WorkloadKind:  "Deployment",
		Zone:          "us-east-1",
		Addr:          netip.MustParseAddr("10.10.1.10").AsSlice(),
		Port:          345555,
		Protocol:      castpb.NetflowProtocol_NETFLOW_PROTOCOL_TCP,
		Destinations: []*castpb.NetflowDestination{
			{
				Namespace:    "n2",
				PodName:      "p2",
				WorkloadName: "w2",
				WorkloadKind: "Deployment",
				Zone:         "us-east-2",
				DnsQuestion:  "service.n2.svc.cluster.local.",
				Addr:         netip.MustParseAddr("10.10.1.15").AsSlice(),
				Port:         80,
				TxBytes:      10,
				TxPackets:    2,
			},
		},
	})
	r.NoError(err)
}

func newClickhouseConn(clickhouseAddr string) (clickhouse.Conn, error) {
	return clickhouse.Open(&clickhouse.Options{
		Addr: []string{clickhouseAddr},
		Auth: clickhouse.Auth{
			Database: "kvisor",
			Username: "kvisor",
			Password: "kvisor",
		},
		Settings: clickhouse.Settings{
			"allow_experimental_object_type": "1",
		},
		MaxOpenConns: 20,
	})
}

func startClickhouseDB(t *testing.T) (string, func()) {
	ctx := context.Background()
	hz := wait.NewHTTPStrategy("/ping")
	hz.Port = "8123/tcp"
	req := testcontainers.ContainerRequest{
		Image:        "clickhouse/clickhouse-server:24.2.3.70-alpine",
		ExposedPorts: []string{"9000/tcp", "8123/tcp"},
		WaitingFor:   hz,
		Env: map[string]string{
			"CLICKHOUSE_USER":                      "kvisor",
			"CLICKHOUSE_PASSWORD":                  "kvisor",
			"CLICKHOUSE_DB":                        "kvisor",
			"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
		},
	}
	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	mport, err := cont.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return "127.0.0.1:" + mport.Port(), func() {
		if err := cont.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err.Error())
		}
	}
}
