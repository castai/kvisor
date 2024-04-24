package signature

import (
	"fmt"

	v1 "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/net/packet"
	"github.com/castai/kvisor/pkg/proc"
	"github.com/elastic/go-freelru"
)

var _ Signature = (*SOCKS5Detected)(nil)

type SOCKS5DetectionState uint8

const (
	SOCKS5Unknown SOCKS5DetectionState = iota
	SOCKS5InitialClientRequestReceived
	SOCKS5InitialClientRequestSend
	SOCKS5InitialServerResponseSend
	SOCKS5InitialServerResponseReceived
)

const DefaultSOCKS5SignatureCacheSize = 1024

type SOCKS5DetectionSignatureConfig struct {
	CacheSize uint32
}

type SOCKS5Detected struct {
	detectionStateCache freelru.Cache[proc.PID, SOCKS5DetectionState]
}

func NewSOCKS5DetectedSignature(cfg SOCKS5DetectionSignatureConfig) (Signature, error) {
	var cacheSize uint32 = DefaultSOCKS5SignatureCacheSize
	if cfg.CacheSize > 0 {
		cacheSize = DefaultSOCKS5SignatureCacheSize
	}

	cache, err := freelru.NewSynced[proc.PID, SOCKS5DetectionState](cacheSize, func(u uint32) uint32 {
		return u
	})
	if err != nil {
		return nil, err
	}

	return &SOCKS5Detected{
		detectionStateCache: cache,
	}, nil
}

func (*SOCKS5Detected) GetMetadata() SignatureMetadata {
	return SignatureMetadata{
		ID:      v1.SignatureEventID_SIGNATURE_SOCKS5_DETECTED,
		Name:    "socks5_detected",
		Version: "0.0.1",
		TargetEvents: []events.ID{
			events.NetPacketSOCKS5Base,
		},
	}
}

func toProtocolAddressType(t packet.SOCKS5AddressType) v1.SOCKS5AddressType {
	switch t {
	case packet.SOCKS5AddressTypeIPv4:
		return v1.SOCKS5AddressType_SOCKS5_ADDRESS_TYPE_IPv4
	case packet.SOCKS5AddressTypeDomainName:
		return v1.SOCKS5AddressType_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME
	case packet.SOCKS5AddressTypeIPv6:
		return v1.SOCKS5AddressType_SOCKS5_ADDRESS_TYPE_IPv6
	}

	return v1.SOCKS5AddressType_SOCKS5_ADDRESS_TYPE_UNKNOWN
}

func toProtocolFlowDirection(f types.FlowDirection) v1.FlowDirection {
	switch f {
	case types.FlowDirectionIngress:
		return v1.FlowDirection_FLOW_INGRESS
	case types.FlowDirectionEgress:
		return v1.FlowDirection_FLOW_EGRESS
	}
	return v1.FlowDirection_FLOW_UNKNOWN
}

func toSOCKS5Finding(state SOCKS5DetectionState, flowDirection types.FlowDirection, msg packet.SOCKS5RequestOrReply) *v1.SOCKS5DetectedFinding {
	var role v1.SOCKS5Role

	switch state {
	case SOCKS5InitialClientRequestSend, SOCKS5InitialServerResponseReceived:
		role = v1.SOCKS5Role_SOCKS5_ROLE_CLIENT
	case SOCKS5InitialClientRequestReceived, SOCKS5InitialServerResponseSend:
		role = v1.SOCKS5Role_SOCKS5_ROLE_SERVER
	default:
		role = v1.SOCKS5Role_SOCKS5_ROLE_UNKNOWN
	}

	return &v1.SOCKS5DetectedFinding{
		Role:          role,
		FlowDirection: toProtocolFlowDirection(flowDirection),
		CmdOrReply:    uint32(msg.CmdOrReply),
		AddressType:   toProtocolAddressType(msg.AddressType),
		Address:       msg.Address,
		Port:          uint32(msg.Port),
	}
}

func (s *SOCKS5Detected) OnEvent(event *types.Event) *v1.SignatureFinding {
	var networkData []byte

	switch args := event.Args.(type) {
	case types.NetPacketSOCKS5BaseArgs:
		networkData = args.Payload
	default:
		return nil
	}

	payload, _, err := packet.ExtractPayload(networkData)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	message, err := packet.ParseSOCKS5(payload)
	if err != nil {
		return nil
	}

	flowDirection := event.Context.ParseFlowDirection()

	switch msg := message.(type) {
	case packet.SOCKS5InitialClientRequest:
		switch flowDirection {
		case types.FlowDirectionEgress:
			s.detectionStateCache.Add(event.Context.Pid, SOCKS5InitialClientRequestSend)
		case types.FlowDirectionIngress:
			s.detectionStateCache.Add(event.Context.Pid, SOCKS5InitialClientRequestReceived)
		}

		return nil

	case packet.SOCKS5InitialServerResponse:
		switch flowDirection {
		case types.FlowDirectionEgress:
			s.detectionStateCache.Add(event.Context.Pid, SOCKS5InitialServerResponseSend)
		case types.FlowDirectionIngress:
			s.detectionStateCache.Add(event.Context.Pid, SOCKS5InitialServerResponseReceived)
		}

		return nil

	case packet.SOCKS5RequestOrReply:
		state, found := s.detectionStateCache.Get(event.Context.Pid)
		if !found {
			state = SOCKS5Unknown
		}

		return &v1.SignatureFinding{
			Data: &v1.SignatureFinding_Socks5Detected{
				Socks5Detected: toSOCKS5Finding(state, flowDirection, msg),
			},
		}
	}

	return &v1.SignatureFinding{}
}
