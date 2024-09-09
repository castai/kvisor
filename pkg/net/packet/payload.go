package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
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

type PacketDetails struct {
	Payload []byte
	Proto   SubProtocol
	Src     netip.AddrPort
	Dst     netip.AddrPort
}

// ExtractPacketDetails will try to extract the payload for a given IPv4/IPv6 packet.
func ExtractPacketDetails(data []byte) (PacketDetails, error) {
	if len(data) == 0 {
		return PacketDetails{}, ErrNoData
	}

	version := data[0] >> 4

	switch version {
	case ipV4:
		return extractPayloadV4(data)
	case ipV6:
		return extractPayloadV6(data)
	default:
		return PacketDetails{}, fmt.Errorf("cannot extract payload for IP packet version `%d`: %w", version, ErrUnsupportedIPVersion)
	}
}

func extractPayloadV4(data []byte) (PacketDetails, error) {
	subProtocol := SubProtocol(data[9])
	totalLength := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < totalLength {
		return PacketDetails{}, ErrPacketTooSmall
	}

	subOffset := int((data[0] & 0x0F) << 2)

	if subOffset > totalLength {
		return PacketDetails{}, ErrOffsetBiggerThanData
	}

	srcAddr := netip.AddrFrom4([4]byte(data[12:16]))
	dstAddr := netip.AddrFrom4([4]byte(data[16:20]))

	switch subProtocol {
	case SubProtocolTCP:
		if (totalLength - subOffset) < minTcpHeaderLength {
			return PacketDetails{}, ErrSubProtocolDataTooSmall
		}

		srcPort := binary.BigEndian.Uint16(data[subOffset : subOffset+2])
		dstPort := binary.BigEndian.Uint16(data[subOffset+2 : subOffset+4])

		dataOffset := (data[subOffset+12] & 0xF0) >> 2

		return PacketDetails{
			Payload: data[subOffset+int(dataOffset) : totalLength],
			Proto:   subProtocol,
			Src:     netip.AddrPortFrom(srcAddr, srcPort),
			Dst:     netip.AddrPortFrom(dstAddr, dstPort),
		}, nil

	case SubProtocolUDP:
		if (totalLength - subOffset) < udpHeaderLength {
			return PacketDetails{}, ErrSubProtocolDataTooSmall
		}

		srcPort := binary.BigEndian.Uint16(data[subOffset : subOffset+2])
		dstPort := binary.BigEndian.Uint16(data[subOffset+2 : subOffset+4])

		return PacketDetails{
			Payload: data[subOffset+udpHeaderLength : totalLength],
			Proto:   subProtocol,
			Src:     netip.AddrPortFrom(srcAddr, srcPort),
			Dst:     netip.AddrPortFrom(dstAddr, dstPort),
		}, nil
	}

	return PacketDetails{}, fmt.Errorf("error while parsing sub protocol `%d`: %w", subProtocol, ErrUnsupportedSubProtocol)
}

func extractPayloadV6(data []byte) (PacketDetails, error) {
	subProtocol := SubProtocol(data[6])
	totalLength := int(binary.BigEndian.Uint16(data[4:6])) + ipV6HeaderLength
	if len(data) < totalLength {
		return PacketDetails{}, ErrPacketTooSmall
	}

	srcAddr := netip.AddrFrom16([16]byte(data[8:24]))
	dstAddr := netip.AddrFrom16([16]byte(data[24:40]))

	// We ignore ipv6 extension headers for now.
	subOffset := ipV6HeaderLength

	switch subProtocol {
	case SubProtocolTCP:
		if (totalLength - subOffset) < minTcpHeaderLength {
			return PacketDetails{}, ErrSubProtocolDataTooSmall
		}
		srcPort := binary.BigEndian.Uint16(data[subOffset : subOffset+2])
		dstPort := binary.BigEndian.Uint16(data[subOffset+2 : subOffset+4])
		dataOffset := (data[subOffset+12] & 0xF0) >> 2

		return PacketDetails{
			Payload: data[subOffset+int(dataOffset) : totalLength],
			Proto:   subProtocol,
			Src:     netip.AddrPortFrom(srcAddr, srcPort),
			Dst:     netip.AddrPortFrom(dstAddr, dstPort),
		}, nil

	case SubProtocolUDP:
		if (totalLength - subOffset) < udpHeaderLength {
			return PacketDetails{}, ErrSubProtocolDataTooSmall
		}
		srcPort := binary.BigEndian.Uint16(data[subOffset : subOffset+2])
		dstPort := binary.BigEndian.Uint16(data[subOffset+2 : subOffset+4])

		return PacketDetails{
			Payload: data[subOffset+udpHeaderLength : totalLength],
			Proto:   subProtocol,
			Src:     netip.AddrPortFrom(srcAddr, srcPort),
			Dst:     netip.AddrPortFrom(dstAddr, dstPort),
		}, nil
	}

	return PacketDetails{}, nil
}
