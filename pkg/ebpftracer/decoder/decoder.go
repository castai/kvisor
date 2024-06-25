package decoder

//go:generate go run ../../../tools/codegen/... ../events.go ../types/args.go args_decoder.go decoder

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
)

type Decoder struct {
	log    *logging.Logger
	buffer []byte
	cursor int
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

func (decoder *Decoder) DecodeSignalContext(ctx *types.SignalContext) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < ctx.GetSizeBytes() {
		return fmt.Errorf("signal context buffer size [%d] smaller than %d", len(decoder.buffer[offset:]), ctx.GetSizeBytes())
	}

	ctx.EventID = events.ID(binary.LittleEndian.Uint32(decoder.buffer[offset : offset+4]))

	decoder.cursor += ctx.GetSizeBytes()

	return nil
}

// DecodeContext translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.eventContext struct.
func (decoder *Decoder) DecodeContext(ctx *types.EventContext) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < ctx.GetSizeBytes() {
		return fmt.Errorf("context buffer size [%d] smaller than %d", len(decoder.buffer[offset:]), ctx.GetSizeBytes())
	}

	// event_context start
	ctx.Ts = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+8])

	// task_context start
	ctx.StartTime = binary.LittleEndian.Uint64(decoder.buffer[offset+8 : offset+16])
	ctx.CgroupID = binary.LittleEndian.Uint64(decoder.buffer[offset+16 : offset+24])
	ctx.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+24 : offset+28])
	ctx.Tid = binary.LittleEndian.Uint32(decoder.buffer[offset+28 : offset+32])
	ctx.Ppid = binary.LittleEndian.Uint32(decoder.buffer[offset+32 : offset+36])
	ctx.HostPid = binary.LittleEndian.Uint32(decoder.buffer[offset+36 : offset+40])
	ctx.HostTid = binary.LittleEndian.Uint32(decoder.buffer[offset+40 : offset+44])
	ctx.HostPpid = binary.LittleEndian.Uint32(decoder.buffer[offset+44 : offset+48])
	ctx.NodeHostPid = binary.LittleEndian.Uint32(decoder.buffer[offset+48 : offset+52])
	ctx.Uid = binary.LittleEndian.Uint32(decoder.buffer[offset+52 : offset+56])
	ctx.MntID = binary.LittleEndian.Uint32(decoder.buffer[offset+56 : offset+60])
	ctx.PidID = binary.LittleEndian.Uint32(decoder.buffer[offset+60 : offset+64])
	_ = copy(ctx.Comm[:], decoder.buffer[offset+64:offset+80])
	_ = copy(ctx.UtsName[:], decoder.buffer[offset+80:offset+96])
	ctx.Flags = binary.LittleEndian.Uint32(decoder.buffer[offset+96 : offset+100])
	ctx.LeaderStartTime = binary.LittleEndian.Uint64(decoder.buffer[offset+100 : offset+108])
	ctx.ParentStartTime = binary.LittleEndian.Uint64(decoder.buffer[offset+108 : offset+116])
	// task_context end
	// 4 bytes padding

	ctx.EventID = events.ID(binary.LittleEndian.Uint32(decoder.buffer[offset+120 : offset+124]))
	ctx.Syscall = int32(binary.LittleEndian.Uint32(decoder.buffer[offset+124 : offset+128]))
	ctx.MatchedPolicies = binary.LittleEndian.Uint64(decoder.buffer[offset+128 : offset+136])
	ctx.Retval = int64(binary.LittleEndian.Uint64(decoder.buffer[offset+136 : offset+144]))
	ctx.StackID = binary.LittleEndian.Uint32(decoder.buffer[offset+144 : offset+148])
	ctx.ProcessorId = binary.LittleEndian.Uint16(decoder.buffer[offset+148 : offset+150])
	// 2 byte padding
	// event_context end

	decoder.cursor += ctx.GetSizeBytes()
	return nil
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
	*msg = int16(binary.LittleEndian.Uint16(decoder.buffer[offset : offset+readAmount]))
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
	*msg = int32(binary.LittleEndian.Uint32(decoder.buffer[offset : offset+readAmount]))
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
	*msg = int64(binary.LittleEndian.Uint64(decoder.buffer[decoder.cursor : decoder.cursor+readAmount]))
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
		msg[i] = int32(binary.LittleEndian.Uint32(decoder.buffer[decoder.cursor : decoder.cursor+4]))
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

// DecodeSlimCred translates data from the decoder buffer, starting from the decoder cursor, to SlimCred struct.
func (decoder *Decoder) DecodeSlimCred(slimCred *types.SlimCred) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < 80 {
		return ErrBufferTooShort
	}
	slimCred.Uid = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+4])
	slimCred.Gid = binary.LittleEndian.Uint32(decoder.buffer[offset+4 : offset+8])
	slimCred.Suid = binary.LittleEndian.Uint32(decoder.buffer[offset+8 : offset+12])
	slimCred.Sgid = binary.LittleEndian.Uint32(decoder.buffer[offset+12 : offset+16])
	slimCred.Euid = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	slimCred.Egid = binary.LittleEndian.Uint32(decoder.buffer[offset+20 : offset+24])
	slimCred.Fsuid = binary.LittleEndian.Uint32(decoder.buffer[offset+24 : offset+28])
	slimCred.Fsgid = binary.LittleEndian.Uint32(decoder.buffer[offset+28 : offset+32])
	slimCred.UserNamespace = binary.LittleEndian.Uint32(decoder.buffer[offset+32 : offset+36])
	slimCred.SecureBits = binary.LittleEndian.Uint32(decoder.buffer[offset+36 : offset+40])
	slimCred.CapInheritable = binary.LittleEndian.Uint64(decoder.buffer[offset+40 : offset+48])
	slimCred.CapPermitted = binary.LittleEndian.Uint64(decoder.buffer[offset+48 : offset+56])
	slimCred.CapEffective = binary.LittleEndian.Uint64(decoder.buffer[offset+56 : offset+64])
	slimCred.CapBounding = binary.LittleEndian.Uint64(decoder.buffer[offset+64 : offset+72])
	slimCred.CapAmbient = binary.LittleEndian.Uint64(decoder.buffer[offset+72 : offset+80])
	decoder.cursor += int(slimCred.GetSizeBytes())
	return nil
}

// DecodeChunkMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.ChunkMeta struct.
func (decoder *Decoder) DecodeChunkMeta(chunkMeta *types.ChunkMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(chunkMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	chunkMeta.BinType = types.BinType(decoder.buffer[offset])
	chunkMeta.CgroupID = binary.LittleEndian.Uint64(decoder.buffer[offset+1 : offset+9])
	_ = copy(chunkMeta.Metadata[:], decoder.buffer[offset+9:offset+37])
	chunkMeta.Size = int32(binary.LittleEndian.Uint32(decoder.buffer[offset+37 : offset+41]))
	chunkMeta.Off = binary.LittleEndian.Uint64(decoder.buffer[offset+41 : offset+49])
	decoder.cursor += int(chunkMeta.GetSizeBytes())
	return nil
}

// DecodeVfsFileMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.VfsFileMeta struct.
func (decoder *Decoder) DecodeVfsFileMeta(vfsFileMeta *types.VfsFileMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(vfsFileMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	vfsFileMeta.DevID = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+4])
	vfsFileMeta.Inode = binary.LittleEndian.Uint64(decoder.buffer[offset+4 : offset+12])
	vfsFileMeta.Mode = binary.LittleEndian.Uint32(decoder.buffer[offset+12 : offset+16])
	vfsFileMeta.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	decoder.cursor += int(vfsFileMeta.GetSizeBytes())
	return nil
}

// DecodeKernelModuleMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.KernelModuleMeta struct.
func (decoder *Decoder) DecodeKernelModuleMeta(kernelModuleMeta *types.KernelModuleMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(kernelModuleMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	kernelModuleMeta.DevID = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+4])
	kernelModuleMeta.Inode = binary.LittleEndian.Uint64(decoder.buffer[offset+4 : offset+12])
	kernelModuleMeta.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+12 : offset+16])
	kernelModuleMeta.Size = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	decoder.cursor += int(kernelModuleMeta.GetSizeBytes())
	return nil
}

// DecodeBpfObjectMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.BpfObjectMeta struct.
func (decoder *Decoder) DecodeBpfObjectMeta(bpfObjectMeta *types.BpfObjectMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(bpfObjectMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	_ = copy(bpfObjectMeta.Name[:], decoder.buffer[offset:offset+16])
	bpfObjectMeta.Rand = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	bpfObjectMeta.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+20 : offset+24])
	bpfObjectMeta.Size = binary.LittleEndian.Uint32(decoder.buffer[offset+24 : offset+28])
	decoder.cursor += int(bpfObjectMeta.GetSizeBytes())
	return nil
}

// DecodeMprotectWriteMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.MprotectWriteMeta struct.
func (decoder *Decoder) DecodeMprotectWriteMeta(mprotectWriteMeta *types.MprotectWriteMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(mprotectWriteMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	mprotectWriteMeta.Ts = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+8])
	mprotectWriteMeta.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+8 : offset+12])

	decoder.cursor += int(mprotectWriteMeta.GetSizeBytes())
	return nil
}

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

var dnsPacketParser = &layers.DNS{}

func (decoder *Decoder) ReadProtoDNS() (*types.ProtoDNS, error) {
	data, err := decoder.ReadMaxByteSliceFromBuff(eventMaxByteSliceBufferSize(events.NetPacketDNSBase))
	if err != nil {
		return nil, err
	}

	payload, subProtocol, err := packet.ExtractPayload(data)
	if err != nil {
		return nil, err
	}

	if subProtocol == packet.SubProtocolTCP {
		if len(payload) < 2 {
			return nil, errDNSMessageNotComplete
		}

		// DNS over TCP prefixes the DNS message with a two octet length field. If the payload is not as big as this specified length,
		// then we cannot parse the packet, as part of the DNS message will be send in a later one.
		// For more information see https://datatracker.ietf.org/doc/html/rfc1035.html#section-4.2.2
		length := int(binary.BigEndian.Uint16(payload[:2]))
		if len(payload)+2 < length {
			return nil, errDNSMessageNotComplete
		}
		payload = payload[2:]
	}
	if err := dnsPacketParser.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}

	pbDNS := &castpb.DNS{
		Answers: make([]*castpb.DNSAnswers, len(dnsPacketParser.Answers)),
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

	return pbDNS, nil
}

func addrPort(family uint16, ip [16]byte, port uint16) netip.AddrPort {
	switch types.SockAddrFamily(family) {
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
