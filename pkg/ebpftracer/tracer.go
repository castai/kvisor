package ebpftracer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
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
	"github.com/castai/kvisor/pkg/metrics"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/castai/kvisor/pkg/processtree"
	"github.com/castai/kvisor/pkg/system"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
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
	GetContainerForCgroup(ctx context.Context, cgroup cgroup.ID) (*containers.Container, error)
	AddContainerByCgroupID(ctx context.Context, cgroupID cgroup.ID) (cont *containers.Container, rerrr error)
	CleanupCgroup(cgroup cgroup.ID)
}

type CgroupClient interface {
	LoadCgroup(id cgroup.ID, path string)
	CleanupCgroup(cgroup cgroup.ID)
	IsDefaultHierarchy(uint32) bool
}

type processTreeCollector interface {
	ProcessStarted(eventTime time.Time, containerID string, p processtree.Process)
	ProcessForked(eventTime time.Time, containerID string, parent processtree.ProcessKey, processKey processtree.ProcessKey)
	ProcessExited(eventTime time.Time, containerID string, processKey processtree.ProcessKey, parentProcessKey processtree.ProcessKey, exitTime uint64)
}

type Config struct {
	BTFPath                string
	EventsPerCPUBuffer     int
	EventsOutputChanSize   int
	DefaultCgroupsVersion  string `validate:"required,oneof=V1 V2"`
	DebugEnabled           bool
	ContainerClient        ContainerClient
	CgroupClient           CgroupClient
	SignatureEngine        *signature.SignatureEngine
	MountNamespacePIDStore *types.PIDsPerNamespace
	// All PIPs reported from ebpf will be normalized to this PID namespace
	HomePIDNS                          proc.NamespaceID
	AllowAnyEvent                      bool
	NetflowOutputChanSize              int
	NetflowSampleSubmitIntervalSeconds uint64
	NetflowGrouping                    NetflowGrouping
	TrackSyscallStats                  bool
	ProcessTreeCollector               processTreeCollector
	MetricsReportingEnabled            bool
}

type cgroupCleanupRequest struct {
	cgroupID     cgroup.ID
	cleanupAfter time.Time
}

type Tracer struct {
	log *logging.Logger
	cfg Config

	bootTime uint64

	module    *module
	eventsSet map[events.ID]definition

	policyMu          sync.Mutex
	policy            *Policy
	eventPoliciesMap  map[events.ID]*EventPolicy
	cgroupEventPolicy map[cgroup.ID]map[events.ID]*cgroupEventPolicy
	signatureEventMap map[events.ID]struct{}

	eventsChan        chan *types.Event
	netflowEventsChan chan *types.Event

	removedCgroupsMu sync.Mutex
	removedCgroups   map[uint64]struct{}

	dnsPacketParser *layers.DNS

	cgroupCleanupMu         sync.Mutex
	requestedCgroupCleanups []cgroupCleanupRequest

	cleanupTimerTickRate      time.Duration
	cgroupCleanupDelay        time.Duration
	metricExportTimerTickRate time.Duration
}

func New(log *logging.Logger, cfg Config) *Tracer {
	if err := validator.New().Struct(cfg); err != nil {
		panic(fmt.Errorf("invalid ebpftracer config: %w", err).Error())
	}

	log = log.WithField("component", "ebpftracer")
	m := newModule(log, moduleConfig{
		BTFObjPath: cfg.BTFPath,
	})

	if cfg.EventsPerCPUBuffer == 0 {
		cfg.EventsPerCPUBuffer = 8192
	}
	if cfg.EventsOutputChanSize == 0 {
		cfg.EventsOutputChanSize = 16384
	}

	t := &Tracer{
		log:                       log,
		cfg:                       cfg,
		module:                    m,
		bootTime:                  uint64(system.GetBootTime().UnixNano()),
		eventsChan:                make(chan *types.Event, cfg.EventsOutputChanSize),
		netflowEventsChan:         make(chan *types.Event, cfg.NetflowOutputChanSize),
		removedCgroups:            map[uint64]struct{}{},
		eventPoliciesMap:          map[events.ID]*EventPolicy{},
		cgroupEventPolicy:         map[uint64]map[events.ID]*cgroupEventPolicy{},
		dnsPacketParser:           &layers.DNS{},
		signatureEventMap:         map[events.ID]struct{}{},
		cleanupTimerTickRate:      1 * time.Minute,
		cgroupCleanupDelay:        1 * time.Minute,
		metricExportTimerTickRate: 5 * time.Second,
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
	if t.cfg.DebugEnabled {
		errg.Go(func() error {
			return t.debugEventsLoop(ctx)
		})
	}
	errg.Go(func() error {
		return t.eventsReadLoop(ctx)
	})
	errg.Go(func() error {
		return t.signalEventsReadLoop(ctx)
	})
	errg.Go(func() error {
		return t.cgroupCleanupLoop(ctx)
	})

	if t.cfg.MetricsReportingEnabled {
		errg.Go(func() error {
			return t.exportEBPFMetricsLoop(ctx)
		})
	}

	return errg.Wait()
}

func (t *Tracer) Events() <-chan *types.Event {
	return t.eventsChan
}

func (t *Tracer) NetflowEvents() <-chan *types.Event {
	return t.netflowEventsChan
}

func (t *Tracer) GetEventName(id events.ID) string {
	if def, found := t.eventsSet[id]; found {
		return def.name
	}
	return ""
}

func (t *Tracer) signalEventsReadLoop(ctx context.Context) error {
	return t.runPerfBufReaderLoop(ctx, t.module.objects.SignalEvents)
}

func (t *Tracer) eventsReadLoop(ctx context.Context) error {
	return t.runPerfBufReaderLoop(ctx, t.module.objects.Events)
}

func (t *Tracer) runPerfBufReaderLoop(ctx context.Context, target *ebpf.Map) error {
	eventsReader, err := perf.NewReader(target, t.cfg.EventsPerCPUBuffer)
	if err != nil {
		return err
	}
	defer eventsReader.Close()

	// Allocate message decoder and perf record once.
	// Under the hood per event reader will reuse and grow raw sample backing bytes slice.
	ebpfMsgDecoder := decoder.NewEventDecoder(t.log, []byte{})
	var record perf.Record

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := eventsReader.ReadInto(&record)
		if err != nil {
			if t.cfg.DebugEnabled {
				t.log.Warnf("reading event: %v", err)
			}
			continue
		}
		if record.LostSamples > 0 {
			t.log.Warnf("lost %d events", record.LostSamples)
			metrics.AgentKernelLostEventsTotal.Add(float64(record.LostSamples))
			continue
		}

		// Reset decoder with new raw sample bytes.
		ebpfMsgDecoder.Reset(record.RawSample)
		if err := t.decodeAndExportEvent(ctx, ebpfMsgDecoder); err != nil {
			if errors.Is(err, decoder.ErrTooManyArguments) {
				data := ebpfMsgDecoder.Buffer()
				t.log.Errorf("decoding event: too many arguments for event. payload=%s, err=%v",
					base64.StdEncoding.EncodeToString(data), err)
			} else if t.cfg.DebugEnabled || errors.Is(err, ErrPanic) {
				t.log.Errorf("decoding event: %v", err)
			}
			metrics.AgentDecodeEventErrorsTotal.Inc()
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
	for _, event := range t.policy.Events {
		event := event
		t.eventPoliciesMap[event.ID] = event
	}

	eventsParams := getParamTypes(t.eventsSet)
	requiredEventsIDs := make(map[events.ID]struct{})
	for _, event := range policy.Events {
		event := event
		t.eventPoliciesMap[event.ID] = event
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
	t.log.Debugf("required events: %v", lo.Map(lo.Keys(requiredEventsIDs), func(item events.ID, index int) string {
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
	for id := range requiredEventsIDs {
		def, found := t.eventsSet[id]
		if !found {
			return fmt.Errorf("missing event definition for id %d", id)
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
	config := t.computeConfigValues(policy)
	if err := t.module.objects.ConfigMap.Update(uint32(0), config, 0); err != nil {
		return fmt.Errorf("updating config map: %w", err)
	}

	// Initialize tail call dependencies.
	for _, tailCall := range tailCalls {
		err := t.initTailCall(tailCall)
		if err != nil {
			return fmt.Errorf("failed to initialize tail call: %w", err)
		}
	}

	return nil
}

func marshalEventConfig(eventsParams map[events.ID][]ArgType, id events.ID) []byte {
	eventConfigVal := make([]byte, 16)
	// bitmap of policies that require this event to be submitted
	binary.LittleEndian.PutUint64(eventConfigVal[0:8], 1)
	// encoded event's parameter types
	var paramTypes uint64
	params := eventsParams[id]
	for n, paramType := range params {
		paramTypes = paramTypes | (uint64(paramType) << (8 * n))
	}
	binary.LittleEndian.PutUint64(eventConfigVal[8:16], paramTypes)
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

const (
	optExecEnv uint32 = 1 << iota
	optCaptureFilesWrite
	optExtractDynCode
	optStackAddresses
	optCaptureModules
	optCgroupV1
	optTranslateFDFilePath
	optCaptureBpf
	optCaptureFileRead
)

func (t *Tracer) getOptionsConfig(p *Policy) uint32 {
	var cOptVal uint32

	if p.Output.ExecEnv {
		cOptVal = cOptVal | optExecEnv
	}
	if p.Output.StackAddresses {
		cOptVal = cOptVal | optStackAddresses
	}
	// TODO: Check other options.
	//if t.config.Capture.FileWrite.Capture {
	//	cOptVal = cOptVal | optCaptureFilesWrite
	//}
	//if t.config.Capture.FileRead.Capture {
	//	cOptVal = cOptVal | optCaptureFileRead
	//}
	//if t.config.Capture.Module {
	//	cOptVal = cOptVal | optCaptureModules
	//}
	//if t.config.Capture.Bpf {
	//	cOptVal = cOptVal | optCaptureBpf
	//}
	//if t.config.Capture.Mem {
	//	cOptVal = cOptVal | optExtractDynCode
	//}
	//if t.config.Output.ParseArgumentsFDs {
	//	cOptVal = cOptVal | optTranslateFDFilePath
	//}
	if t.cfg.DefaultCgroupsVersion == "V1" {
		cOptVal = cOptVal | optCgroupV1
	}
	return cOptVal
}

func (t *Tracer) computeConfigValues(p *Policy) []byte {
	// config_entry
	configVal := make([]byte, 256)

	// tracee_pid
	binary.LittleEndian.PutUint32(configVal[0:4], uint32(os.Getpid()))
	// options
	binary.LittleEndian.PutUint32(configVal[4:8], t.getOptionsConfig(p))
	// cgroup_v1_hid
	//binary.LittleEndian.PutUint32(configVal[8:12], uint32(t.containers.GetDefaultCgroupHierarchyID()))
	binary.LittleEndian.PutUint32(configVal[8:12], 0)
	// padding
	binary.LittleEndian.PutUint32(configVal[12:16], 0)

	id := 0
	byteIndex := id / 8
	bitOffset := id % 8

	// enabled_scopes
	configVal[216+byteIndex] |= 1 << bitOffset

	// compute all policies internals
	//t.config.Policies.Compute()

	// uid_max
	//binary.LittleEndian.PutUint64(configVal[224:232], t.config.Policies.UIDFilterMax())
	//// uid_min
	//binary.LittleEndian.PutUint64(configVal[232:240], t.config.Policies.UIDFilterMin())
	//// pid_max
	//binary.LittleEndian.PutUint64(configVal[240:248], t.config.Policies.PIDFilterMax())
	//// pid_min
	//binary.LittleEndian.PutUint64(configVal[248:256], t.config.Policies.PIDFilterMin())

	return configVal
}

func (t *Tracer) initTailCall(tailCall TailCall) error {
	tailCallIndexes := tailCall.indexes
	// Pick eBPF program file descriptor.
	bpfProgFD := uint32(tailCall.ebpfProg.FD())
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

func (t *Tracer) debugEventsLoop(ctx context.Context) error {
	rd, err := perf.NewReader(t.module.objects.DebugEvents, 2048)
	if err != nil {
		return fmt.Errorf("creating debug events perf reader: %w", err)
	}

	var e types.RawDebugEvent
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		v, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			continue
		}

		if v.LostSamples > 0 {
			t.log.Warnf("lost samples %d", v.LostSamples)
		}
		if len(v.RawSample) == 0 {
			continue
		}
		if err := binary.Read(bytes.NewBuffer(v.RawSample), binary.LittleEndian, &e); err != nil {
			return fmt.Errorf("read event binary: %w", err)
		}

		msg := e.String()
		fmt.Printf("%s\n", msg)
	}
}

func (t *Tracer) allowedByPolicyPre(ctx *types.EventContext) error {
	policy := t.getPolicy(ctx.EventID, ctx.CgroupID)

	if policy != nil {
		return policy.allowPre(ctx)
	}

	// No policy.
	return nil
}

func (t *Tracer) allowedByPolicy(eventID events.ID, cgroupID uint64, event *types.Event) error {
	policy := t.getPolicy(eventID, cgroupID)

	if policy != nil {
		return policy.allow(event)
	}

	// No policy.
	return nil
}

func (t *Tracer) getPolicy(eventID events.ID, cgroupID uint64) *cgroupEventPolicy {
	t.policyMu.Lock()
	defer t.policyMu.Unlock()

	eventPolicy, found := t.eventPoliciesMap[eventID]
	if found {
		cgPolicyMap, found := t.cgroupEventPolicy[cgroupID]

		if !found {
			cgPolicyMap = make(map[events.ID]*cgroupEventPolicy)
			t.cgroupEventPolicy[cgroupID] = cgPolicyMap
		}

		cgPolicy, found := cgPolicyMap[eventID]

		if !found {
			cgPolicy = newCgroupEventPolicy(eventPolicy)
			t.cgroupEventPolicy[cgroupID][eventID] = cgPolicy
		}
		return cgPolicy
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
	t.policyMu.Lock()
	t.removedCgroupsMu.Lock()
	for _, id := range cgroupIDs {
		delete(t.cgroupEventPolicy, id)
		t.removedCgroups[id] = struct{}{}
	}
	t.policyMu.Unlock()
	t.removedCgroupsMu.Unlock()

	for _, id := range cgroupIDs {
		t.cfg.ContainerClient.CleanupCgroup(id)
		t.cfg.CgroupClient.CleanupCgroup(id)
	}
}
