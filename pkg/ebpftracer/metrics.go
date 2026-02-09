package ebpftracer

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/castai/kvisor/cmd/agent/daemon/metrics"
	"github.com/castai/logging"
	"github.com/cilium/ebpf"
)

const (
	bpfStatsFile = "/proc/sys/kernel/bpf_stats_enabled"
)

var noopCleanup = func() {}

// Must be kept in sync with `enum metric` defined in types.h.
type eBPFMetric int

const (
	UnknownMetric eBPFMetric = iota
	noFreeScratchBuffer
	noFreeScratchBufferSocketSetState
	noFreeScratchBufferNetflows
	signalEventsRingbufDiscard
	eventsRingbufDiscard
	skbEventsRingbufDiscard
	skbCtxCgroupFallback
	skbMissingExistingCtx
)

func (m eBPFMetric) String() string {
	switch m {
	case noFreeScratchBuffer:
		return "no_free_scratch_buffer"
	case noFreeScratchBufferSocketSetState:
		return "no_free_scratch_buffer_socket_set_state"
	case noFreeScratchBufferNetflows:
		return "no_free_scratch_buffer_netflows"
	case signalEventsRingbufDiscard:
		return "signal_events_ringbuf_discard"
	case eventsRingbufDiscard:
		return "events_ringbuf_discard"
	case skbEventsRingbufDiscard:
		return "skb_events_ringbuf_discard"
	case skbCtxCgroupFallback:
		return "skb_ctx_cgroup_fallback"
	case skbMissingExistingCtx:
		return "skb_missing_existing_ctx"
	default:
		return "unknown"
	}
}

func (t *Tracer) exportMetricsLoop(ctx context.Context) error {
	exportTimer := time.NewTicker(t.metricExportTimerTickRate)
	defer func() {
		exportTimer.Stop()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exportTimer.C:
		}

		if t.cfg.MetricsReporting.TracerMetricsEnabled {
			if err := t.exportEBPFTracerMetrics(); err != nil {
				t.log.Warnf("error while trying to export eBPF tracer metrics: %v", err)
			}
		}

		if t.cfg.MetricsReporting.ProgramMetricsEnabled {
			t.exportEBPFProgramMetrics()
		}
	}
}

func (t *Tracer) exportEBPFTracerMetrics() error {
	iter := t.module.objects.Metrics.Iterate()
	metric := uint32(0)
	counter := uint64(0)

	for iter.Next(&metric, &counter) {
		name := eBPFMetric(metric).String()
		metrics.EBPFExposedMetrics.WithLabelValues(name).Set(float64(counter))
		t.logInternalEbpfTracerMetric(name, counter)
	}
	if err := iter.Err(); err != nil {
		return err
	}

	return nil
}

func (t *Tracer) logInternalEbpfTracerMetric(metricName string, counter uint64) {
	curr := t.currentTracerEbpfMetrics[metricName]
	t.currentTracerEbpfMetrics[metricName] = counter
	diff := counter - curr
	if diff > 0 {
		t.log.Warnf("ebpf issue, metric=%s value=%d pod=%s", metricName, diff, t.cfg.PodName)
	}
}

func (t *Tracer) exportEBPFProgramMetrics() {
	programValue := reflect.ValueOf(t.module.objects.tracerPrograms)
	tracerProgramsType := programValue.Type()

	for i := 0; i < programValue.NumField(); i++ {
		field := tracerProgramsType.Field(i)
		fieldVal := programValue.Field(i)

		programName, found := field.Tag.Lookup("ebpf")
		// The generated programs struct should not have any field without a tag, but in case it
		// happens, we just skip it.
		if !found {
			t.log.Errorf("got ebpf program field without tag: field name: %s", field.Name)
			continue
		}

		ebpfProg, ok := fieldVal.Interface().(*ebpf.Program)
		// This is highly unlikely to happen, but just in case e.g. something changes in the way
		// ebpf2go generates those structs, log an error.
		if !ok {
			t.log.Errorf("got ebpf prog field with unexpected type: field name: %s, type: %t", field.Name, fieldVal.Interface())
			continue
		}

		if ebpfProg == nil {
			t.log.Infof("ebpf prog field `%s` is nil", field.Name)
			continue
		}

		info, err := extractProgramInfo(ebpfProg.FD())
		if err != nil {
			t.log.Warnf("cannot extract program info for field `%s`: %v", field.Name, err)
			continue
		}

		metrics.EBPFProgramRunTimeMetrics.WithLabelValues(programName).Set(float64(info.runTime.Milliseconds()))
		metrics.EBPFProgramRunCountMetrics.WithLabelValues(programName).Set(float64(info.runCount))
	}
}

// The following functions have been copied from https://github.com/cloudflare/ebpf_exporter/blob/master/exporter/program_info.go

type programInfo struct {
	id       int
	tag      string
	runTime  time.Duration
	runCount int
}

func extractProgramInfo(fd int) (programInfo, error) {
	info := programInfo{}

	name := fmt.Sprintf("/proc/self/fdinfo/%d", fd)

	file, err := os.Open(name)
	if err != nil {
		return info, fmt.Errorf("can't open %s: %w", name, err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		switch fields[0] {
		case "prog_tag:":
			info.tag = fields[1]
		case "prog_id:":
			info.id, err = strconv.Atoi(fields[1])
			if err != nil {
				return info, fmt.Errorf("error parsing prog id %q as int: %w", fields[1], err)
			}
		case "run_time_ns:":
			runTimeNs, err := strconv.Atoi(fields[1])
			if err != nil {
				return info, fmt.Errorf("error parsing prog run time duration %q as int: %w", fields[1], err)
			}
			info.runTime = time.Nanosecond * time.Duration(runTimeNs)
		case "run_cnt:":
			info.runCount, err = strconv.Atoi(fields[1])
			if err != nil {
				return info, fmt.Errorf("error parsing prog run count %q as int: %w", fields[1], err)
			}
		}
	}

	if err = scanner.Err(); err != nil {
		return info, fmt.Errorf("error scanning: %w", err)
	}

	return info, nil
}

func EnabledBPFStats(log *logging.Logger) (func(), error) {
	closer, err := ebpf.EnableStats(ebpfStats)
	if err == nil {
		log.Info("successfully enabled bpf stats via syscall")
		return func() {
			err := closer.Close()
			if err != nil {
				log.Errorf("got error when trying to close BPF stats: %v", err)
			}
		}, nil
	}

	log.Warn("couldn't enable ebpf stats via syscall, fallback to procfs")

	// If we cannot enable it BPF stats via the eBPF syscall, lets fallback to proc.
	// The syscall requires Linux >= 5.8

	return enabledBPFStatsProcFS(log)
}

func bpfStatsEnabled() (bool, error) {
	f, err := os.Open(bpfStatsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, fmt.Errorf("error opening %q: %w", bpfStatsFile, err)
	}

	defer f.Close()

	buf := make([]byte, 1)

	_, err = f.Read(buf)
	if err != nil {
		return false, fmt.Errorf("error reading %q: %w", bpfStatsFile, err)
	}

	// 0x31 is '1' in ascii
	return buf[0] == 0x31, nil
}

// End copied functions from cloudflare.
func setBPFStatsEnabled(enabled bool) error {
	f, err := os.OpenFile(bpfStatsFile, os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	var payload []byte

	if enabled {
		payload = []byte{'1'}
	} else {
		payload = []byte{'0'}
	}

	_, err = f.Write(payload)
	if err != nil {
		return err
	}

	return nil
}

func enabledBPFStatsProcFS(log *logging.Logger) (func(), error) {
	isBPFEnabled, err := bpfStatsEnabled()
	if err != nil {
		return noopCleanup, fmt.Errorf("cannot check if bpf stats are enabled: %w", err)
	}

	if isBPFEnabled {
		// Nothing to do
		return noopCleanup, nil
	}

	log.Info("enabling bpf stats")
	err = setBPFStatsEnabled(true)
	if err != nil {

		return noopCleanup, fmt.Errorf("error while trying to enable bpf stats: %w", err)
	}

	// We need to disable bpf stats again, as the overhead is somewhat expensive.
	return func() {
		err := setBPFStatsEnabled(false)
		if err != nil {
			log.Errorf("error while trying to disable bpf stats for cleanup: %v", err)
		}
	}, nil
}
