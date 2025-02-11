package ebpftracer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/castai/kvisor/pkg/cgroup"
	"github.com/castai/kvisor/pkg/containers"
	"github.com/castai/kvisor/pkg/ebpftracer/decoder"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/signature"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/castai/kvisor/pkg/system"
	"github.com/cespare/xxhash/v2"
	"github.com/cilium/ebpf"
	"github.com/elastic/go-freelru"
	"github.com/go-playground/validator/v10"
	"github.com/google/gopacket/layers"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
)

// ActualDestinationGetter is used to find actual destination ip.
// Usually this info is obtained from conntrack.
type ActualDestinationGetter interface {
	GetDestination(src, dst netip.AddrPort) (netip.AddrPort, bool)
}

type ContainerClient interface {
	GetOrLoadContainerByCgroupID(ctx context.Context, cgroup cgroup.ID) (*containers.Container, error)
	AddContainerByCgroupID(ctx context.Context, cgroupID cgroup.ID) (cont *containers.Container, rerrr error)
	CleanupCgroup(cgroup cgroup.ID)
}

type CgroupClient interface {
	GetCgroupsRootPath() string
	LoadCgroup(id cgroup.ID, path string)
	CleanupCgroup(cgroup cgroup.ID)
	IsDefaultHierarchy(uint32) bool
}

type processTreeCollector interface {
	ProcessStarted(eventTime time.Time, containerID string, p processtree.Process)
	ProcessForked(eventTime time.Time, containerID string, parent processtree.ProcessKey, processKey processtree.ProcessKey)
	ProcessExited(eventTime time.Time, containerID string, processKey processtree.ProcessKey, parentProcessKey processtree.ProcessKey, exitTime uint64)
}

type MetricsReportingConfig struct {
	ProgramMetricsEnabled bool
	TracerMetricsEnabled  bool
}

func (m MetricsReportingConfig) Enabled() bool {
	return m.ProgramMetricsEnabled || m.TracerMetricsEnabled
}

type Config struct {
	BTFPath string

	SignalEventsRingBufferSize uint32 `validate:"required"`
	EventsRingBufferSize       uint32 `validate:"required"`
	SkbEventsRingBufferSize    uint32 `validate:"required"`

	EventsOutputChanSize   int
	DefaultCgroupsVersion  string `validate:"required,oneof=V1 V2"`
	DebugEnabled           bool
	AutomountCgroupv2      bool
	ContainerClient        ContainerClient
	CgroupClient           CgroupClient
	SignatureEngine        *signature.SignatureEngine
	MountNamespacePIDStore *types.PIDsPerNamespace
	// All PIPs reported from ebpf will be normalized to this PID namespace
	HomePIDNS                          proc.NamespaceID
	AllowAnyEvent                      bool
	NetflowSampleSubmitIntervalSeconds uint64
	NetflowGrouping                    NetflowGrouping
	TrackSyscallStats                  bool
	ProcessTreeCollector               processTreeCollector
	MetricsReporting                   MetricsReportingConfig
	PodName                            string
	FingerprintSize                    uint32
}

type cgroupCleanupRequest struct {
	cgroupID     cgroup.ID
	cleanupAfter time.Time
}

type fingerprintKey struct {
	cgroupID    cgroup.ID
	fingerprint uint64
}

type Tracer struct {
	log *logging.Logger
	cfg Config

	bootTime uint64

	module    *module
	eventsSet map[events.ID]definition

	policy   *Policy
	policyMu sync.Mutex

	signatureEventMap map[events.ID]struct{}

	eventsChan chan *types.Event

	removedCgroupsMu sync.Mutex
	removedCgroups   map[uint64]struct{}

	dnsPacketParser *layers.DNS

	cgroupCleanupMu         sync.Mutex
	requestedCgroupCleanups []cgroupCleanupRequest

	cleanupTimerTickRate      time.Duration
	cgroupCleanupDelay        time.Duration
	metricExportTimerTickRate time.Duration

	currentTracerEbpfMetrics map[string]uint64

	// fingerprints cache is used for events deduplication.
	fingerprintsDigest *xxhash.Digest
	fingerprints       freelru.Cache[fingerprintKey, struct{}]

	// dumpEvent is used in playground test to dump event bytes for testing.
	dumpEvent bool
}

func New(log *logging.Logger, cfg Config) *Tracer {
	if err := validator.New().Struct(cfg); err != nil {
		panic(fmt.Errorf("invalid ebpftracer config: %w", err).Error())
	}

	log = log.WithField("component", "ebpftracer")
	m := newModule(log)

	if cfg.EventsOutputChanSize == 0 {
		cfg.EventsOutputChanSize = 16384
	}
	if cfg.FingerprintSize == 0 {
		cfg.FingerprintSize = 10000
	}

	fingerprints, err := freelru.New[fingerprintKey, struct{}](cfg.FingerprintSize, func(k fingerprintKey) uint32 {
		return uint32(k.fingerprint) // nolint:gosec
	})
	if err != nil {
		panic(err)
	}
	fingerprints.SetLifetime(10 * time.Second)

	t := &Tracer{
		log:                       log,
		cfg:                       cfg,
		module:                    m,
		bootTime:                  uint64(system.GetBootTime().UnixNano()), // nolint:gosec
		eventsChan:                make(chan *types.Event, cfg.EventsOutputChanSize),
		removedCgroups:            map[uint64]struct{}{},
		dnsPacketParser:           &layers.DNS{},
		signatureEventMap:         map[events.ID]struct{}{},
		cleanupTimerTickRate:      10 * time.Second,
		cgroupCleanupDelay:        10 * time.Second,
		metricExportTimerTickRate: 5 * time.Second,
		currentTracerEbpfMetrics:  map[string]uint64{},
		fingerprints:              fingerprints,
		fingerprintsDigest:        xxhash.New(),
	}

	return t
}

func (t *Tracer) Load() error {
	if err := t.module.load(t.cfg); err != nil {
		return fmt.Errorf("loading ebpf module: %w", err)
	}
	t.eventsSet = newEventsDefinitionSet(t.module.objects)
	return nil
}

func (t *Tracer) Close() error {
	return t.module.close()
}

func (t *Tracer) Run(ctx context.Context) error {
	t.log.Infof("running")
	defer t.log.Infof("stopping")

	if !t.module.loaded.Load() {
		return errors.New("tracer is not loaded")
	}
	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return t.eventsReadLoop(ctx)
	})
	errg.Go(func() error {
		return t.signalEventsReadLoop(ctx)
	})
	errg.Go(func() error {
		return t.skbEventsReadLoop(ctx)
	})
	errg.Go(func() error {
		return t.cgroupCleanupLoop(ctx)
	})

	if t.cfg.MetricsReporting.Enabled() {
		errg.Go(func() error {
			return t.exportMetricsLoop(ctx)
		})
	}

	return errg.Wait()
}

func (t *Tracer) Events() <-chan *types.Event {
	return t.eventsChan
}

func (t *Tracer) GetEventName(id events.ID) string {
	if def, found := t.eventsSet[id]; found {
		return def.name
	}
	return ""
}

func (t *Tracer) skbEventsReadLoop(ctx context.Context) error {
	return t.runPerfBufReaderLoop(ctx, t.module.objects.SkbEvents)
}

func (t *Tracer) signalEventsReadLoop(ctx context.Context) error {
	return t.runPerfBufReaderLoop(ctx, t.module.objects.SignalEvents)
}

func (t *Tracer) eventsReadLoop(ctx context.Context) error {
	return t.runPerfBufReaderLoop(ctx, t.module.objects.Events)
}

type ringbufRecord struct {
	buf []byte
}

func (t *Tracer) runPerfBufReaderLoop(ctx context.Context, target *ebpf.Map) error {
	eventsReader, err := newRingbufReader(target)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		if err := eventsReader.close(); err != nil {
			t.log.Warnf("closing events reader: %v", err)
		}
	}()

	// Allocate message decoder and perf record once.
	// Under the hood per event reader will reuse and grow raw sample backing bytes slice.
	ebpfMsgDecoder := decoder.NewEventDecoder(t.log, []byte{})
	var record ringbufRecord

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := eventsReader.read(&record)
		if err != nil {
			if t.cfg.DebugEnabled {
				t.log.Warnf("reading event: %v", err)
			}
			continue
		}

		// Reset decoder with new raw sample bytes.
		ebpfMsgDecoder.Reset(record.buf)
		if err := t.decodeAndExportEvent(ctx, ebpfMsgDecoder); err != nil {
			continue
		}
	}
}

func (t *Tracer) findAllRequiredEvents(id events.ID, out map[events.ID]struct{}) {
	// No need to load the whole dependency tree twice
	if _, found := out[id]; found {
		return
	}

	def := t.eventsSet[id]
	out[id] = struct{}{}
	for _, def := range def.dependencies.ids {
		t.findAllRequiredEvents(def, out)
	}
}

func (t *Tracer) ApplyPolicy(policy *Policy) error {
	if !t.module.loaded.Load() {
		return errors.New("tracer is not loaded")
	}
	t.policyMu.Lock()
	defer t.policyMu.Unlock()

	if t.policy != nil {
		// TODO(Kvisord): Here we can add policy diff with previous one and dynamically update policy.
		return errors.New("policy update is not supported yet")
	}

	t.policy = policy

	eventsParams := getParamTypes(t.eventsSet)
	requiredEventsIDs := make(map[events.ID]struct{})
	for _, event := range policy.Events {
		event := event
		t.findAllRequiredEvents(event.ID, requiredEventsIDs)
	}
	if t.cfg.SignatureEngine != nil {
		requiredSignatureEvents := policy.SignatureEvents
		for _, eventID := range requiredSignatureEvents {
			t.signatureEventMap[eventID] = struct{}{}
		}
		for _, eventID := range requiredSignatureEvents {
			t.findAllRequiredEvents(eventID, requiredEventsIDs)
		}
	}

	for _, eventID := range policy.SystemEvents {
		t.findAllRequiredEvents(eventID, requiredEventsIDs)
	}
	t.log.Infof("required events: %v", lo.Map(lo.Keys(requiredEventsIDs), func(item events.ID, index int) string {
		def, found := t.eventsSet[item]
		if found {
			return def.name
		}
		return strconv.Itoa(int(item))
	}))

	eventsBpfMapConfig := make(map[events.ID][]byte)

	objs := t.module.objects

	var tailCalls []TailCall
	probesToAttach := map[handle]bool{}
	initializeExistingSockets := false

	for id := range requiredEventsIDs {
		def, found := t.eventsSet[id]
		if !found {
			return fmt.Errorf("missing event definition for id %d", id)
		}

		if def.requiredOptions.socketsInitialized {
			initializeExistingSockets = true
		}

		tailCalls = append(tailCalls, def.dependencies.tailCalls...)
		if def.syscall {
			probesToAttach[ProbeSyscallEnter__Internal] = true
			probesToAttach[ProbeSyscallExit__Internal] = true
			// Add default tail calls for syscall events.
			if len(def.dependencies.tailCalls) == 0 && !def.dependencies.skipDefaultTailCalls {
				tailCalls = append(tailCalls, getDefaultSyscallTailCalls(objs, def)...)
			}
		}
		for _, dep := range def.dependencies.probes {
			if required, found := probesToAttach[dep.handle]; found {
				if !required {
					probesToAttach[dep.handle] = dep.required
				}
			} else {
				probesToAttach[dep.handle] = dep.required
			}
		}

		eventConfigVal := marshalEventConfig(eventsParams, id)
		eventsBpfMapConfig[id] = eventConfigVal
	}

	// Attach selected probes.
	for handle, required := range probesToAttach {
		if err := t.module.attachProbe(handle); err != nil {
			if required {
				return fmt.Errorf("attaching probe %d: %w", handle, err)
			} else {
				t.log.Warnf("attaching optional probe %d: %v", handle, err)
			}
		}
	}

	// Send events configs in events ebpf map.
	for id, cfg := range eventsBpfMapConfig {
		if err := t.module.objects.EventsMap.Update(&id, cfg, 0); err != nil {
			return fmt.Errorf("updating events map, event %d: %w", id, err)
		}
	}

	// Initialize tail call dependencies.
	for _, tailCall := range tailCalls {
		err := t.initTailCall(tailCall)
		if err != nil {
			return fmt.Errorf("failed to initialize tail call: %w", err)
		}
	}

	if initializeExistingSockets {
		// In case initialized sockets are required, we run the initialization logic after the
		// eBPF handlers are in place, to prevent race conditions/timing issues where the are
		// sockets created between running the iterator and registering the eBPF programs.
		err := t.module.InitializeExistingSockets()
		if err != nil {
			t.log.Warnf("failed to load existing sockets: %v", err)
		}
	}

	return nil
}

func marshalEventConfig(eventsParams map[events.ID][]ArgType, id events.ID) []byte {
	eventConfigVal := make([]byte, 8)
	// encoded event's parameter types
	var paramTypes uint64
	params := eventsParams[id]
	for n, paramType := range params {
		paramTypes = paramTypes | (uint64(paramType) << (8 * n))
	}
	binary.LittleEndian.PutUint64(eventConfigVal[0:8], paramTypes)
	return eventConfigVal
}

func getDefaultSyscallTailCalls(objs *tracerObjects, def definition) []TailCall {
	return []TailCall{
		{objs.SysEnterInitTail, objs.SysEnterInit, []uint32{uint32(def.ID)}},
		{objs.SysEnterSubmitTail, objs.SysEnterSubmit, []uint32{uint32(def.ID)}},
		{objs.SysExitInitTail, objs.SysExitInit, []uint32{uint32(def.ID)}},
		{objs.SysExitSubmitTail, objs.SysExitSubmit, []uint32{uint32(def.ID)}},
	}
}

func getParamTypes(eventsSet map[events.ID]definition) map[events.ID][]ArgType {
	eventsParams := make(map[events.ID][]ArgType)
	for _, eventDefinition := range eventsSet {
		id := eventDefinition.ID
		params := eventDefinition.params
		for _, param := range params {
			eventsParams[id] = append(eventsParams[id], getParamType(param.Type))
		}
	}
	return eventsParams
}

func (t *Tracer) initTailCall(tailCall TailCall) error {
	tailCallIndexes := tailCall.indexes
	// Pick eBPF program file descriptor.
	bpfProgFD := uint32(tailCall.ebpfProg.FD()) // nolint:gosec
	if tailCall.ebpfProg.FD() < 0 {
		return fmt.Errorf("ebpf tail call map fd is negative")
	}

	t.log.Debugf("init tail call, map=%s, prog=%s", tailCall.ebpfMap.String(), tailCall.ebpfProg.String())

	// Pick all indexes (event, or syscall, IDs) the BPF program should be related to.
	for _, index := range tailCallIndexes {
		index := index
		// Special treatment for indexes of syscall events.
		if t.eventsSet[events.ID(index)].syscall {
			// Workaround: Do not map eBPF program to unsupported syscalls (arm64, e.g.)
			if index >= uint32(events.Unsupported) {
				continue
			}
		}
		// Update given eBPF map with the eBPF program file descriptor at given index.
		err := tailCall.ebpfMap.Update(&index, &bpfProgFD, 0)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *Tracer) cgroupCleanupLoop(ctx context.Context) error {
	cleanupTimer := time.NewTicker(t.cleanupTimerTickRate)
	defer func() {
		cleanupTimer.Stop()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-cleanupTimer.C:
		}

		now := time.Now()
		var toCleanup []cgroupCleanupRequest

		t.cgroupCleanupMu.Lock()
		toCleanup, t.requestedCgroupCleanups = splitCleanupRequests(now, t.requestedCgroupCleanups)
		t.cgroupCleanupMu.Unlock()

		cgroupsToCleanup := lo.Map(toCleanup, func(item cgroupCleanupRequest, index int) cgroup.ID {
			return item.cgroupID
		})
		t.removeCgroups(cgroupsToCleanup)

		t.removedCgroupsMu.Lock()
		t.removedCgroups = map[uint64]struct{}{}
		t.removedCgroupsMu.Unlock()
	}
}

// splitCleanupRequests will split the given slice by the first index that is after the provided `now`. The provided
// requests need to be sorted by cleanup date.
func splitCleanupRequests(now time.Time, requests []cgroupCleanupRequest) ([]cgroupCleanupRequest, []cgroupCleanupRequest) {
	splitIdx := len(requests)
	// Requests have to be orderd by cleanup date.
	for i, r := range requests {
		if now.Before(r.cleanupAfter) {
			splitIdx = i
			break
		}
	}

	return requests[:splitIdx], requests[splitIdx:]
}

func (t *Tracer) queueCgroupForRemoval(cgroupID cgroup.ID) {
	t.cgroupCleanupMu.Lock()
	t.requestedCgroupCleanups = append(t.requestedCgroupCleanups, cgroupCleanupRequest{
		cgroupID:     cgroupID,
		cleanupAfter: time.Now().Add(t.cgroupCleanupDelay),
	})
	t.cgroupCleanupMu.Unlock()
}

func (t *Tracer) removeCgroups(cgroupIDs []cgroup.ID) {
	t.removedCgroupsMu.Lock()
	for _, id := range cgroupIDs {
		t.removedCgroups[id] = struct{}{}
	}
	t.removedCgroupsMu.Unlock()

	for _, id := range cgroupIDs {
		t.cfg.ContainerClient.CleanupCgroup(id)
		t.cfg.CgroupClient.CleanupCgroup(id)
	}
}
