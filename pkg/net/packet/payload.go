package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ipV4             = 4
	ipV6             = 6
	ipV4HeaderLength = 20
	ipV6HeaderLength = 40

	minTcpHeaderLength = 20
	udpHeaderLength    = 8
)

type SubProtocol byte

const (
	UnsupportedSubProtocol SubProtocol = 0
	SubProtocolTCP         SubProtocol = 0x06
	SubProtocolUDP         SubProtocol = 0x11
)

var subProtocolName = map[SubProtocol]string{
	SubProtocolTCP: "TCP",
	SubProtocolUDP: "UDP",
}

func (s SubProtocol) String() string {
	if name, found := subProtocolName[s]; found {
		return name
	}

	return "UNKNOWN"
}

var (
	ErrUnsupportedIPVersion    = errors.New("ip version not supported")
	ErrUnsupportedSubProtocol  = errors.New("sub protocol not supported")
	ErrOffsetBiggerThanData    = errors.New("sub protocol offset is larger than given data")
	ErrSubProtocolDataTooSmall = errors.New("sub protocol data is too small")
	ErrPacketTooSmall          = errors.New("packet to small")
	ErrNoData                  = errors.New("no data provided")
)

// ExtractPayload will try to extract the payload for a given IPv4/IPv6 packet.
func ExtractPayload(data []byte) ([]byte, SubProtocol, error) {
	if len(data) == 0 {
		return nil, UnsupportedSubProtocol, ErrNoData
	}

	version := data[0] >> 4

	switch version {
	case 4:
		return extractPayloadV4(data)
	case 6:
		return extractPayloadV6(data)
	default:
		return nil, UnsupportedSubProtocol, fmt.Errorf("cannot extract payload for IP packet version `%d`: %w", version, ErrUnsupportedIPVersion)
	}
}

func extractPayloadV4(data []byte) ([]byte, SubProtocol, error) {
	subProtocol := SubProtocol(data[9])
	totalLength := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < totalLength {
		return nil, UnsupportedSubProtocol, ErrPacketTooSmall
	}

	subOffset := int((data[0] & 0x0F) << 2)

	if subOffset > totalLength {
		return nil, UnsupportedSubProtocol, ErrOffsetBiggerThanData
	}

	switch subProtocol {
	case SubProtocolTCP:
		if (totalLength - subOffset) < minTcpHeaderLength {
			return nil, UnsupportedSubProtocol, ErrSubProtocolDataTooSmall
		}
		dataOffset := (data[subOffset+12] & 0xF0) >> 2
		return data[subOffset+int(dataOffset) : totalLength], SubProtocolTCP, nil

	case SubProtocolUDP:
		if (totalLength - subOffset) < udpHeaderLength {
			return nil, UnsupportedSubProtocol, ErrSubProtocolDataTooSmall
		}
		return data[subOffset+udpHeaderLength : totalLength], SubProtocolUDP, nil
	}

	return nil, UnsupportedSubProtocol, fmt.Errorf("error while parsing sub protocol `%d`: %w", subProtocol, ErrUnsupportedSubProtocol)
}

func extractPayloadV6(data []byte) ([]byte, SubProtocol, error) {
	subProtocol := SubProtocol(data[6])
	totalLength := int(binary.BigEndian.Uint16(data[4:6])) + ipV6HeaderLength
	if len(data) < totalLength {
		return nil, UnsupportedSubProtocol, ErrPacketTooSmall
	}
	// We ignore ipv6 extension headers for now.
	subOffset := ipV6HeaderLength

	switch subProtocol {
	case SubProtocolTCP:
		if (totalLength - subOffset) < minTcpHeaderLength {
			return nil, UnsupportedSubProtocol, ErrSubProtocolDataTooSmall
		}
		dataOffset := (data[subOffset+12] & 0xF0) >> 2
		return data[subOffset+int(dataOffset) : totalLength], SubProtocolTCP, nil

	case SubProtocolUDP:
		if (totalLength - subOffset) < udpHeaderLength {
			return nil, UnsupportedSubProtocol, ErrSubProtocolDataTooSmall
		}
		return data[subOffset+udpHeaderLength : totalLength], SubProtocolUDP, nil
	}

	return nil, UnsupportedSubProtocol, nil
}
