package conntrack

import (
	"fmt"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestConntrack(t *testing.T) {
	t.Skip() // This test used for debug only.

	r := require.New(t)
	log := logging.New(&logging.Config{
		Level: slog.LevelDebug,
	})

	ct, err := NewClient(log)
	r.NoError(err)
	src := netip.MustParseAddrPort("10.244.0.7:42861")
	dsr := netip.MustParseAddrPort("10.244.0.65:8090")
	res, found := ct.GetDestination(src, dsr)
	_ = res
	_ = found
	fmt.Print("res", res, found)
}
