package decoder

//go:generate go run ../../../tools/codegen/... ../events.go ../types/args.go args_decoder.go decoder
//go:generate go run ../../../tools/eventcontextcodegen/... ../tracer_arm64_bpfel.go ../types/protocol.go context_decoder_arm64_gen.go arm64
//go:generate go run ../../../tools/eventcontextcodegen/... ../tracer_x86_bpfel.go ../types/protocol.go context_decoder_x86_gen.go x86

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	castpb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/pkg/ebpftracer/events"
	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/castai/kvisor/pkg/net/packet"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

type Decoder struct {
	log    *logging.Logger
	buffer []byte
	cursor int
}

func (decoder *Decoder) Buffer() []byte {
	return decoder.buffer
}

var ErrBufferTooShort = errors.New("can't read context from buffer: buffer too short")

func NewEventDecoder(log *logging.Logger, rawBuffer []byte) *Decoder {
	return &Decoder{
		log:    log,
		buffer: rawBuffer,
		cursor: 0,
	}
}

func (decoder *Decoder) Reset(buf []byte) {
	decoder.buffer = buf
	decoder.cursor = 0
}

func (decoder *Decoder) SeekForward(amount int) {
	decoder.cursor += amount
}

// BuffLen returns the total length of the buffer owned by decoder.
func (decoder *Decoder) BuffLen() int {
	return len(decoder.buffer)
}

// ReadAmountBytes returns the total amount of bytes that decoder has read from its buffer up until now.
func (decoder *Decoder) ReadAmountBytes() int {
	return decoder.cursor
}

func (decoder *Decoder) SkipUint8() error {
	readAmount := 1
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	decoder.cursor += readAmount
	return nil
}

// DecodeUint8 translates data from the decoder buffer, starting from the decoder cursor, to uint8.
func (decoder *Decoder) DecodeUint8(msg *uint8) error {
	readAmount := 1
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = decoder.buffer[decoder.cursor]
	decoder.cursor += readAmount
	return nil
}

// DecodeInt8 translates data from the decoder buffer, starting from the decoder cursor, to int8.
func (decoder *Decoder) DecodeInt8(msg *int8) error {
	readAmount := 1
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = int8(decoder.buffer[offset])
	decoder.cursor += readAmount
	return nil
}

// DecodeUint16 translates data from the decoder buffer, starting from the decoder cursor, to uint16.
func (decoder *Decoder) DecodeUint16(msg *uint16) error {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.LittleEndian.Uint16(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeUint16BigEndian translates data from the decoder buffer, starting from the decoder cursor, to uint16.
func (decoder *Decoder) DecodeUint16BigEndian(msg *uint16) error {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.BigEndian.Uint16(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeInt16 translates data from the decoder buffer, starting from the decoder cursor, to int16.
func (decoder *Decoder) DecodeInt16(msg *int16) error {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = int16(binary.LittleEndian.Uint16(decoder.buffer[offset : offset+readAmount])) // nolint:gosec
	decoder.cursor += readAmount
	return nil
}

// DecodeUint32 translates data from the decoder buffer, starting from the decoder cursor, to uint32.
func (decoder *Decoder) DecodeUint32(msg *uint32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeUint32BigEndian translates data from the decoder buffer, starting from the decoder cursor, to uint32.
func (decoder *Decoder) DecodeUint32BigEndian(msg *uint32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.BigEndian.Uint32(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeInt32 translates data from the decoder buffer, starting from the decoder cursor, to int32.
func (decoder *Decoder) DecodeInt32(msg *int32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = int32(binary.LittleEndian.Uint32(decoder.buffer[offset : offset+readAmount])) // nolint:gosec
	decoder.cursor += readAmount
	return nil
}

// DecodeUint64 translates data from the decoder buffer, starting from the decoder cursor, to uint64.
func (decoder *Decoder) DecodeUint64(msg *uint64) error {
	readAmount := 8
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeInt64 translates data from the decoder buffer, starting from the decoder cursor, to int64.
func (decoder *Decoder) DecodeInt64(msg *int64) error {
	readAmount := 8
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = int64(binary.LittleEndian.Uint64(decoder.buffer[decoder.cursor : decoder.cursor+readAmount])) // nolint:gosec
	decoder.cursor += readAmount
	return nil
}

// DecodeBool translates data from the decoder buffer, starting from the decoder cursor, to bool.
func (decoder *Decoder) DecodeBool(msg *bool) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < 1 {
		return ErrBufferTooShort
	}
	*msg = (decoder.buffer[offset] != 0)
	decoder.cursor++
	return nil
}

// DecodeBytes copies from the decoder buffer, starting from the decoder cursor, to msg, size bytes.
func (decoder *Decoder) DecodeBytes(msg []byte, size int) error {
	offset := decoder.cursor
	bufferLen := len(decoder.buffer[offset:])
	if bufferLen < size {
		return ErrBufferTooShort
	}
	_ = copy(msg[:], decoder.buffer[offset:offset+size])
	decoder.cursor += size
	return nil
}

// DecodeBytesNoCopy gets bytes from current offset to given size.
func (decoder *Decoder) DecodeBytesNoCopy(size int) ([]byte, error) {
	offset := decoder.cursor
	bufferLen := len(decoder.buffer[offset:])
	if bufferLen < size {
		return nil, ErrBufferTooShort
	}
	res := decoder.buffer[offset : offset+size]
	decoder.cursor += size
	return res, nil
}

// DecodeIntArray translate from the decoder buffer, starting from the decoder cursor, to msg, size * 4 bytes (in order to get int32).
func (decoder *Decoder) DecodeIntArray(msg []int32, size int) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < size*4 {
		return ErrBufferTooShort
	}
	for i := 0; i < size; i++ {
		msg[i] = int32(binary.LittleEndian.Uint32(decoder.buffer[decoder.cursor : decoder.cursor+4])) // nolint:gosec
		decoder.cursor += 4
	}
	return nil
}

// DecodeUint64Array translate from the decoder buffer, starting from the decoder cursor, to msg, size * 8 bytes (in order to get int64).
func (decoder *Decoder) DecodeUint64Array(msg *[]uint64) error {
	var arrLen uint16
	err := decoder.DecodeUint16(&arrLen)
	if err != nil {
		return fmt.Errorf("error reading ulong array number of elements: %w", err)
	}
	for i := 0; i < int(arrLen); i++ {
		var element uint64
		err := decoder.DecodeUint64(&element)
		if err != nil {
			return fmt.Errorf("can't read element %d uint64 from buffer: %w", i, err)
		}
		*msg = append(*msg, element)
	}
	return nil
}

// DecodeKernelModuleMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.KernelModuleMeta struct.
func (decoder *Decoder) ReadSockaddrFromBuff() (types.Sockaddr, error) {
	var familyInt int16
	err := decoder.DecodeInt16(&familyInt)
	if err != nil {
		return nil, err
	}
	family := types.SockAddrFamily(familyInt)
	switch family {
	case types.AF_UNIX:
		/*
			http://man7.org/linux/man-pages/man7/unix.7.html
			struct sockaddr_un {
					sa_family_t sun_family;     // AF_UNIX
					char        sun_path[108];  // Pathname
			};
		*/
		sunPath, err := decoder.ReadStringVarFromBuff(108)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_un: %w", err)
		}
		return types.UnixSockAddr{
			Path: sunPath,
		}, nil
	case types.AF_INET:
		/*
			http://man7.org/linux/man-pages/man7/ip.7.html
			struct sockaddr_in {
				sa_family_t    sin_family; // address family: AF_INET
				in_port_t      sin_port;   // port in network byte order
				struct in_addr sin_addr;   // internet address
				// byte        padding[8];// https://elixir.bootlin.com/linux/v4.20.17/source/include/uapi/linux/in.h#L232
			};
			struct in_addr {
				uint32_t       s_addr;     // address in network byte order
			};
		*/
		var port uint16
		err = decoder.DecodeUint16BigEndian(&port)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %w", err)
		}
		addr, err := decoder.ReadByteSliceFromBuff(4)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %w", err)
		}
		_, err = decoder.ReadByteSliceFromBuff(8) // discard padding
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %w", err)
		}
		return types.Ip4SockAddr{
			Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte(addr)), port),
		}, nil
	case types.AF_INET6:
		/*
			struct sockaddr_in6 {
				sa_family_t     sin6_family;   // AF_INET6
				in_port_t       sin6_port;     // port number
				uint32_t        sin6_flowinfo; // IPv6 flow information
				struct in6_addr sin6_addr;     // IPv6 address
				uint32_t        sin6_scope_id; // Scope ID (new in 2.4)
			};

			struct in6_addr {
				unsigned char   s6_addr[16];   // IPv6 address
			};
		*/
		var port uint16
		err = decoder.DecodeUint16BigEndian(&port)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %w", err)
		}

		var flowinfo uint32
		err = decoder.DecodeUint32BigEndian(&flowinfo)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %w", err)
		}
		addr, err := decoder.ReadByteSliceFromBuff(16)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %w", err)
		}
		var scopeid uint32
		err = decoder.DecodeUint32BigEndian(&scopeid)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %w", err)
		}

		return types.Ip6SockAddr{
			Addr:     netip.AddrPortFrom(netip.AddrFrom16([16]byte(addr)), port),
			FlowInfo: flowinfo,
			ScopeID:  scopeid,
		}, nil
	}

	return types.NewGenericSockAddr(family), nil
}

func (decoder *Decoder) ReadStringFromBuff() (string, error) {
	var err error
	var size uint32
	err = decoder.DecodeUint32(&size)
	if err != nil {
		return "", fmt.Errorf("error reading string size: %w", err)
	}
	if size > 4096 {
		return "", fmt.Errorf("string size too big: %d", size)
	}
	res, err := decoder.ReadByteSliceFromBuff(int(size - 1)) // last byte is string terminating null
	defer func() {
		var dummy int8
		err := decoder.DecodeInt8(&dummy) // discard last byte which is string terminating null
		if err != nil {
			decoder.log.Warnf("trying to discard last byte: %v", err)
		}
	}()
	if err != nil {
		return "", fmt.Errorf("error reading string arg: %w", err)
	}
	return string(res), nil
}

// readStringVarFromBuff reads a null-terminated string from `buff`
// max length can be passed as `max` to optimize memory allocation, otherwise pass 0
func (decoder *Decoder) ReadStringVarFromBuff(max int) (string, error) {
	var err error
	var char int8
	res := make([]byte, 0, max)
	err = decoder.DecodeInt8(&char)
	if err != nil {
		return "", fmt.Errorf("error reading null terminated string: %w", err)
	}
	var count int
	for count = 1; char != 0 && count < max; count++ {
		res = append(res, byte(char))
		err = decoder.DecodeInt8(&char)
		if err != nil {
			return "", fmt.Errorf("error reading null terminated string: %w", err)
		}
	}
	res = bytes.TrimLeft(res[:], "\000")
	decoder.SeekForward(max - count)
	return string(res), nil
}

func (decoder *Decoder) ReadByteSliceFromBuff(len int) ([]byte, error) {
	res, err := decoder.DecodeBytesNoCopy(len)
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %w", err)
	}
	return res, nil
}

func (decoder *Decoder) ReadMaxByteSliceFromBuff(max int) ([]byte, error) {
	var size uint32
	err := decoder.DecodeUint32(&size)
	if err != nil {
		return nil, fmt.Errorf("error reading byte array size: %w", err)
	}

	if max >= 0 && int(size) > max {
		return nil, fmt.Errorf("byte array size too big: %d", size)
	}

	res, err := decoder.DecodeBytesNoCopy(int(size))
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %w", err)
	}
	return res, nil
}

func (decoder *Decoder) ReadStringArrayFromBuff() ([]string, error) {
	// TODO optimization: create slice after getting arrLen
	var arrLen uint8
	err := decoder.DecodeUint8(&arrLen)
	if err != nil {
		return nil, fmt.Errorf("error reading string array number of elements: %w", err)
	}

	ss := make([]string, arrLen)
	for i := 0; i < int(arrLen); i++ {
		s, err := decoder.ReadStringFromBuff()
		if err != nil {
			return nil, fmt.Errorf("error reading string element: %w", err)
		}
		ss[i] = s
	}

	return ss, nil
}

func (decoder *Decoder) ReadArgsArrayFromBuff() ([]string, error) {
	var ss []string
	var arrLen uint32
	var argNum uint32

	err := decoder.DecodeUint32(&arrLen)
	if err != nil {
		return nil, fmt.Errorf("error reading args array length: %w", err)
	}
	err = decoder.DecodeUint32(&argNum)
	if err != nil {
		return nil, fmt.Errorf("error reading args number: %w", err)
	}
	resBytes, err := decoder.ReadByteSliceFromBuff(int(arrLen))
	if err != nil {
		return nil, fmt.Errorf("error reading args array: %w", err)
	}
	ss = strings.Split(string(resBytes), "\x00")
	if ss[len(ss)-1] == "" {
		ss = ss[:len(ss)-1]
	}
	for int(argNum) > len(ss) {
		ss = append(ss, "?")
	}

	return ss, nil
}

func (decoder *Decoder) ReadTimespec() (float64, error) {
	var sec int64
	var nsec int64
	err := decoder.DecodeInt64(&sec)
	if err != nil {
		return 0, err
	}
	err = decoder.DecodeInt64(&nsec)
	if err != nil {
		return 0, err
	}
	return float64(sec) + (float64(nsec) / float64(1000000000)), nil
}

func (decoder *Decoder) ReadAddrTuple() (types.AddrTuple, error) {
	srcAddr := [16]byte{}
	if err := decoder.DecodeBytes(srcAddr[:], len(srcAddr)); err != nil {
		return types.AddrTuple{}, err
	}
	dstAddr := [16]byte{}
	if err := decoder.DecodeBytes(dstAddr[:], len(dstAddr)); err != nil {
		return types.AddrTuple{}, err
	}
	var srcPort uint16
	if err := decoder.DecodeUint16(&srcPort); err != nil {
		return types.AddrTuple{}, err
	}
	var dstPort uint16
	if err := decoder.DecodeUint16(&dstPort); err != nil {
		return types.AddrTuple{}, err
	}
	var family uint16
	if err := decoder.DecodeUint16(&family); err != nil {
		return types.AddrTuple{}, err
	}
	return types.AddrTuple{
		Src: addrPort(family, srcAddr, srcPort),
		Dst: addrPort(family, dstAddr, dstPort),
	}, nil
}

var errDNSMessageNotComplete = errors.New("received dns packet not complete")

// NOTE: This is not thread safe. Since currently only single go-routine reads the data this is fine.
var dnsPacketParser = &layers.DNS{}

func (decoder *Decoder) DecodeDNSLayer(details *packet.PacketDetails) (*layers.DNS, error) {
	if details.Proto == packet.SubProtocolTCP {
		if len(details.Payload) < 2 {
			return nil, errDNSMessageNotComplete
		}

		// DNS over TCP prefixes the DNS message with a two octet length field. If the payload is not as big as this specified length,
		// then we cannot parse the packet, as part of the DNS message will be send in a later one.
		// For more information see https://datatracker.ietf.org/doc/html/rfc1035.html#section-4.2.2
		length := int(binary.BigEndian.Uint16(details.Payload[:2]))
		if len(details.Payload)+2 < length {
			return nil, errDNSMessageNotComplete
		}
		details.Payload = details.Payload[2:]
	}
	if err := dnsPacketParser.DecodeFromBytes(details.Payload, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	return dnsPacketParser, nil
}

func (decoder *Decoder) DecodeDNSAndDetails() (*layers.DNS, packet.PacketDetails, error) {
	var discard uint8
	// Read firsts two bytes and discard. It's mapped to argsnum and index.
	// For network events in most cases there is only 1 argument (payload).
	_ = decoder.DecodeUint8(&discard)
	_ = decoder.DecodeUint8(&discard)

	packetData, err := decoder.ReadMaxByteSliceFromBuff(-1)
	if err != nil {
		return nil, packet.PacketDetails{}, err
	}

	details, err := packet.ExtractPacketDetails(packetData)
	if err != nil {
		return nil, packet.PacketDetails{}, err
	}

	dns, err := decoder.DecodeDNSLayer(&details)
	if err != nil {
		return nil, packet.PacketDetails{}, err
	}
	return dns, details, nil
}

func (decoder *Decoder) ReadProtoDNS() (*types.ProtoDNS, error) {
	data, err := decoder.ReadMaxByteSliceFromBuff(eventMaxByteSliceBufferSize(events.NetPacketDNSBase))
	if err != nil {
		return nil, err
	}

	details, err := packet.ExtractPacketDetails(data)
	if err != nil {
		return nil, err
	}

	if details.Proto == packet.SubProtocolTCP {
		if len(details.Payload) < 2 {
			return nil, errDNSMessageNotComplete
		}

		// DNS over TCP prefixes the DNS message with a two octet length field. If the payload is not as big as this specified length,
		// then we cannot parse the packet, as part of the DNS message will be send in a later one.
		// For more information see https://datatracker.ietf.org/doc/html/rfc1035.html#section-4.2.2
		length := int(binary.BigEndian.Uint16(details.Payload[:2]))
		if len(details.Payload)+2 < length {
			return nil, errDNSMessageNotComplete
		}
		details.Payload = details.Payload[2:]
	}
	if err := dnsPacketParser.DecodeFromBytes(details.Payload, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}

	return ToProtoDNS(&details, dnsPacketParser), nil
}

// ProcessNameString converts raw process name to readable string.
// Since it's a C-like string it can contain NUL byte.
func ProcessNameString(raw []byte) string {
	return unix.ByteSliceToString(raw)
}

func ToProtoDNS(details *packet.PacketDetails, dnsPacketParser *layers.DNS) *castpb.DNS {
	pbDNS := &castpb.DNS{
		Answers: make([]*castpb.DNSAnswers, len(dnsPacketParser.Answers)),
		Tuple: &castpb.Tuple{
			SrcIp:   details.Src.Addr().AsSlice(),
			DstIp:   details.Dst.Addr().AsSlice(),
			SrcPort: uint32(details.Src.Port()),
			DstPort: uint32(details.Dst.Port()),
		},
	}

	for _, v := range dnsPacketParser.Questions {
		pbDNS.DNSQuestionDomain = string(v.Name)
		break
	}

	for i, v := range dnsPacketParser.Answers {
		pbDNS.Answers[i] = &castpb.DNSAnswers{
			Name:  string(v.Name),
			Type:  uint32(v.Type),
			Class: uint32(v.Class),
			Ttl:   v.TTL,
			Ip:    v.IP,
			Cname: string(v.CNAME),
		}
	}
	return pbDNS
}

var ErrWrongSSHVersionPrefix = errors.New("got wrong ssh version prefix")

func (decoder *Decoder) ReadProtoSSH() (*types.ProtoSSH, error) {
	var version string
	var comments string

	payload, err := decoder.ReadMaxByteSliceFromBuff(eventMaxByteSliceBufferSize(events.NetPacketSSHBase))
	if err != nil {
		return nil, err
	}

	details, err := packet.ExtractPacketDetails(payload)
	if err != nil {
		return nil, err
	}

	versionLineFields := bytes.SplitN(bytes.Trim(details.Payload, "\r\n"), []byte{' '}, 2)

	version = string(versionLineFields[0])
	if !strings.HasPrefix(version, "SSH-") {
		return nil, fmt.Errorf("%w: expected `SSH-` got `%s`", ErrWrongSSHVersionPrefix, version)
	}

	if len(versionLineFields) == 2 {
		comments = string(versionLineFields[1])
	}

	return &types.ProtoSSH{
		Version:  version,
		Comments: comments,
		Tuple: &castpb.Tuple{
			SrcIp:   details.Src.Addr().AsSlice(),
			DstIp:   details.Dst.Addr().AsSlice(),
			SrcPort: uint32(details.Src.Port()),
			DstPort: uint32(details.Dst.Port()),
		},
	}, nil
}

func addrPort(family uint16, ip [16]byte, port uint16) netip.AddrPort {
	switch types.SockAddrFamily(family) { // nolint:gosec
	case types.AF_INET:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]}), port)
	}
	return netip.AddrPortFrom(netip.AddrFrom16(ip).Unmap(), port)
}

// PrintUint32IP prints the IP address encoded as a uint32
func PrintUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

// Print16BytesSliceIP prints the IP address encoded as 16 bytes long PrintBytesSliceIP
// It would be more correct to accept a [16]byte instead of variable length slice, but that would cause unnecessary memory copying and type conversions
func Print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}
