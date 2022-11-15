package metrics

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func init() {
	timeSinceFn = func(t time.Time) time.Duration {
		return 1
	}
}

func TestScansTotalMetric(t *testing.T) {
	r := require.New(t)

	IncScansTotal(ScanTypeCloud, nil)
	IncScansTotal(ScanTypeCloud, nil)
	IncScansTotal(ScanTypeImage, errors.New("ups"))

	problems, err := testutil.CollectAndLint(scansTotal)
	r.NoError(err)
	r.Empty(problems)

	expected := `# HELP castai_security_agent_scans_total Counter tracking scans and statuses
# TYPE castai_security_agent_scans_total counter
castai_security_agent_scans_total{scan_status="error",scan_type="image"} 1
castai_security_agent_scans_total{scan_status="ok",scan_type="cloud"} 2
`
	r.NoError(testutil.CollectAndCompare(scansTotal, strings.NewReader(expected)))
}

func TestScansDurationMetric(t *testing.T) {
	r := require.New(t)

	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	ObserveScanDuration(ScanTypeLinter, start)

	problems, err := testutil.CollectAndLint(scansDuration)
	r.NoError(err)
	r.Empty(problems)

	expected := `# HELP castai_security_agent_scans_duration Histogram tracking scan durations in seconds
# TYPE castai_security_agent_scans_duration histogram
castai_security_agent_scans_duration_bucket{scan_type="linter",le="0.05"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="0.1"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="0.25"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="0.5"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="1"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="2.5"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="5"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="10"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="15"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="20"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="30"} 1
castai_security_agent_scans_duration_bucket{scan_type="linter",le="+Inf"} 1
castai_security_agent_scans_duration_sum{scan_type="linter"} 1e-09
castai_security_agent_scans_duration_count{scan_type="linter"} 1
`
	r.NoError(testutil.CollectAndCompare(scansDuration, strings.NewReader(expected)))
}

func TestDeltaSentTotalMetric(t *testing.T) {
	r := require.New(t)

	IncDeltasSentTotal()
	IncDeltasSentTotal()

	problems, err := testutil.CollectAndLint(deltasSentTotal)
	r.NoError(err)
	r.Empty(problems)

	expected := `# HELP castai_security_agent_deltas_total Counter tracking deltas sent
# TYPE castai_security_agent_deltas_total counter
castai_security_agent_deltas_total 2
`
	r.NoError(testutil.CollectAndCompare(deltasSentTotal, strings.NewReader(expected)))
}

func TestImagesCount(t *testing.T) {
	r := require.New(t)

	SetTotalImagesCount(5)
	problems, err := testutil.CollectAndLint(imagesTotalCount)
	r.NoError(err)
	r.Empty(problems)
	expected := `# HELP castai_security_agent_images Gauge for tracking container images count
# TYPE castai_security_agent_images gauge
castai_security_agent_images 5
`
	r.NoError(testutil.CollectAndCompare(imagesTotalCount, strings.NewReader(expected)))

	SetPendingImagesCount(3)
	problems, err = testutil.CollectAndLint(imagesPendingCount)
	r.NoError(err)
	r.Empty(problems)
	expected = `# HELP castai_security_agent_pending_images Gauge for tracking pending container images count
# TYPE castai_security_agent_pending_images gauge
castai_security_agent_pending_images 3
`
	r.NoError(testutil.CollectAndCompare(imagesPendingCount, strings.NewReader(expected)))
}
