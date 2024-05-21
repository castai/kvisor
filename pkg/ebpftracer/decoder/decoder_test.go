package decoder

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

var (
	log *logging.Logger
)

func TestDecodeContext(t *testing.T) {
	buf := new(bytes.Buffer)
	ctxExpected := types.EventContext{
		Ts:              11,
		StartTime:       223,
		CgroupID:        22,
		Pid:             543,
		Tid:             77,
		Ppid:            4567,
		HostPid:         5430,
		HostTid:         124,
		HostPpid:        555,
		NodeHostPid:     51,
		Uid:             9876,
		MntID:           1357,
		PidID:           3758,
		Comm:            [16]byte{1, 3, 5, 3, 1, 5, 56, 6, 7, 32, 2, 4},
		UtsName:         [16]byte{5, 6, 7, 8, 9, 4, 3, 2},
		Flags:           12,
		LeaderStartTime: 10,
		ParentStartTime: 11,
		EventID:         16,
		Syscall:         9,
		MatchedPolicies: 7,
		Retval:          4,
		StackID:         10,
		ProcessorId:     5,
	}
	err := binary.Write(buf, binary.LittleEndian, ctxExpected)
	assert.Equal(t, nil, err)
	var ctxObtained types.EventContext
	rawData := buf.Bytes()
	d := NewEventDecoder(log, rawData, nil)
	cursorBefore := d.cursor
	err = d.DecodeContext(&ctxObtained)
	cursorAfter := d.cursor

	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, ctxExpected, ctxObtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, int(ctxExpected.GetSizeBytes()), cursorAfter-cursorBefore)
}

func TestDecodeSignalContext(t *testing.T) {
	buf := new(bytes.Buffer)
	ctxExpected := types.SignalContext{
		EventID: 100,
	}
	err := binary.Write(buf, binary.LittleEndian, ctxExpected)
	assert.Equal(t, nil, err)
	var ctxObtained types.SignalContext
	rawData := buf.Bytes()
	d := NewEventDecoder(log, rawData, nil)
	cursorBefore := d.cursor
	err = d.DecodeSignalContext(&ctxObtained)
	cursorAfter := d.cursor

	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, ctxExpected, ctxObtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, int(ctxExpected.GetSizeBytes()), cursorAfter-cursorBefore)
}

func TestDecodeUint8(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected uint8 = 42
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained uint8
	err = d.DecodeUint8(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 1, cursorAfter-cursorBefore) // cursor should move 1 byte
}

func TestDecodeInt8(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected int8 = -42
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained int8
	err = d.DecodeInt8(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 1, cursorAfter-cursorBefore) // cursor should move 1 byte
}

func TestDecodeUint16(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected uint16 = 5555
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained uint16
	err = d.DecodeUint16(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 2, cursorAfter-cursorBefore) // cursor should move 2 byte
}

func TestDecodeUint16BigEndian(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected uint16 = 5555
	err := binary.Write(buf, binary.BigEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained uint16
	err = d.DecodeUint16BigEndian(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 2, cursorAfter-cursorBefore) // cursor should move 2 byte
}
func TestDecodeInt16(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected int16 = -3456
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained int16
	err = d.DecodeInt16(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 2, cursorAfter-cursorBefore) // cursor should move 2 byte
}

func TestDecodeUint32(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected uint32 = 5555
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained uint32
	err = d.DecodeUint32(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, cursorAfter-cursorBefore, 4) // cursor should move 4 byte
}

func TestDecodeUint32BigEndian(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected uint32 = 5555
	err := binary.Write(buf, binary.BigEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained uint32
	err = d.DecodeUint32BigEndian(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, cursorAfter-cursorBefore, 4) // cursor should move 4 byte
}
func TestDecodeInt32(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected int32 = -3456
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained int32
	err = d.DecodeInt32(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 4, cursorAfter-cursorBefore) // cursor should move 4 byte
}

func TestDecodeUint64(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected uint64 = 5555
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained uint64
	err = d.DecodeUint64(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 8, cursorAfter-cursorBefore) // cursor should move 8 byte
}

func TestDecodeInt64(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected int64 = -3456
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained int64
	err = d.DecodeInt64(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 8, cursorAfter-cursorBefore) // cursor should move 8 byte
}

func TestDecodeBoolTrue(t *testing.T) {
	buf := new(bytes.Buffer)
	expected := true
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained bool
	err = d.DecodeBool(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 1, cursorAfter-cursorBefore) // cursor should move 1 byte
}

func TestDecodeBoolFalse(t *testing.T) {
	buf := new(bytes.Buffer)
	expected := false
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b, nil)
	cursorBefore := d.cursor
	var obtained bool
	err = d.DecodeBool(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 1, cursorAfter-cursorBefore) // cursor should move 1 byte
}

// TODO DecodeBytes and DecodeIntArray
func TestDecodeBytes(t *testing.T) {
	type JustAStruct struct {
		A1 uint32
		A2 uint64
	}
	expected := JustAStruct{
		A1: 43,
		A2: 444434,
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &expected)
	assert.Equal(t, nil, err)

	var sunPathBuf [12]byte // 12 is the size of JustAStruct
	d := NewEventDecoder(log, buf.Bytes(), nil)
	err = d.DecodeBytes(sunPathBuf[:], 12)
	assert.Equal(t, nil, err)

	r := bytes.NewBuffer(sunPathBuf[:])
	var obtained JustAStruct
	err = binary.Read(r, binary.LittleEndian, &obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeIntArray(t *testing.T) {
	var raw []byte
	raw = append(raw, 1, 2, 3, 4, 5, 6, 7, 8)
	decoder := NewEventDecoder(log, raw, nil)
	var obtained [2]int32
	err := decoder.DecodeIntArray(obtained[:], 2)
	assert.Equal(t, nil, err)
	rawcp := append(raw, 1, 2, 3, 4, 5, 6, 7, 8)
	dataBuff := bytes.NewBuffer(rawcp)
	var expected [2]int32
	err = binary.Read(dataBuff, binary.LittleEndian, &expected)
	assert.Equal(t, nil, err)
	// checking decoding works as expected
	assert.Equal(t, expected, obtained)
}

func TestDecodeSlimCred(t *testing.T) {
	buf := new(bytes.Buffer)
	expected := types.SlimCred{
		Uid:            43,
		Gid:            6789,
		Suid:           987,
		Sgid:           678,
		Euid:           543,
		Egid:           7538,
		Fsuid:          687,
		Fsgid:          3454,
		UserNamespace:  34,
		SecureBits:     456789,
		CapInheritable: 342,
		CapPermitted:   9873,
		CapEffective:   555,
		CapBounding:    5555,
		CapAmbient:     432,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained types.SlimCred
	rawBuf := buf.Bytes()
	d := NewEventDecoder(log, rawBuf, nil)
	err = d.DecodeSlimCred(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeChunkMeta(t *testing.T) {
	buf := new(bytes.Buffer)
	expected := types.ChunkMeta{
		BinType:  54,
		CgroupID: 6543,
		Metadata: [28]byte{5, 4, 3, 5, 6, 7, 4, 54, 3, 32, 4, 4, 4, 4, 4},
		Size:     6543,
		Off:      76543,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained types.ChunkMeta
	rawBuf := buf.Bytes()
	d := NewEventDecoder(log, rawBuf, nil)
	err = d.DecodeChunkMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeVfsWriteMeta(t *testing.T) {
	buf := new(bytes.Buffer)
	expected := types.VfsFileMeta{
		DevID: 54,
		Inode: 543,
		Mode:  654,
		Pid:   98479,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained types.VfsFileMeta
	rawBuf := buf.Bytes()
	d := NewEventDecoder(log, rawBuf, nil)
	err = d.DecodeVfsFileMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeKernelModuleMeta(t *testing.T) {
	buf := new(bytes.Buffer)
	expected := types.KernelModuleMeta{
		DevID: 7489,
		Inode: 543,
		Pid:   7654,
		Size:  4533,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained types.KernelModuleMeta
	rawBuf := buf.Bytes()
	d := NewEventDecoder(log, rawBuf, nil)
	err = d.DecodeKernelModuleMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeBpfObjectMeta(t *testing.T) {
	buf := new(bytes.Buffer)
	expected := types.BpfObjectMeta{
		Name: [16]byte{80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80},
		Rand: 543,
		Pid:  7654,
		Size: 4533,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained types.BpfObjectMeta
	rawBuf := buf.Bytes()
	d := NewEventDecoder(log, rawBuf, nil)
	err = d.DecodeBpfObjectMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeMprotectWriteMeta(t *testing.T) {
	buf := new(bytes.Buffer)
	expected := types.MprotectWriteMeta{
		Pid: 12,
		Ts:  6789,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained types.MprotectWriteMeta
	rawBuf := buf.Bytes()
	d := NewEventDecoder(log, rawBuf, nil)
	err = d.DecodeMprotectWriteMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func BenchmarkDecodeContext(*testing.B) {
	var ctx types.EventContext
	/*
		s := eventContext{
			Ts:          11,
			ProcessorId: 32,
			CgroupID:    22,
			Pid:         543,
			Tid:         77,
			Ppid:        4567,
			HostPid:     5430,
			HostTid:     124,
			HostPpid:    555,
			Uid:         9876,
			MntID:       1357,
			PidID:       3758,
			Comm:        [16]byte{1, 3, 5, 3, 1, 5, 56, 6, 7, 32, 2, 4},
			UtsName:     [16]byte{5, 6, 7, 8, 9, 4, 3, 2},
			EventID:     654,
			Retval:      6543,
			StackID:     6,
			Argnum:      234,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{11, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 176, 1, 0, 0, 0, 0, 0, 0, 31, 2, 0, 0, 77, 0, 0, 0, 215, 17, 0, 0,
		54, 21, 0, 0, 124, 0, 0, 0, 43, 2, 0, 0, 148, 38, 0, 0, 77, 5, 0, 0, 174, 14, 0, 0, 1, 3, 5, 3, 1, 5, 56, 6, 7, 32,
		2, 4, 0, 0, 0, 0, 5, 6, 7, 8, 9, 4, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 142, 2, 0, 0, 143, 25, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 234,
		0, 0, 0}
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeContext(&ctx)
	}
}
func BenchmarkBinaryContext(*testing.B) {
	var ctx types.EventContext
	/*
		s := eventContext{
			Ts:       11,
			CgroupID: 22,
			ProcessorId: 432,
			Pid:      543,
			Tid:      77,
			Ppid:     4567,
			HostPid:  5430,
			HostTid:  124,
			HostPpid: 555,
			Uid:      9876,
			MntID:    1357,
			PidID:    3758,
			Comm:     [16]byte{1, 3, 5, 3, 1, 5, 56, 6, 7, 32, 2, 4},
			UtsName:  [16]byte{5, 6, 7, 8, 9, 4, 3, 2},
			EventID:  654,
			Retval:   6543,
			StackID:  6,
			Argnum:   234,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/

	buffer := []byte{11, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 176, 1, 0, 0, 0, 0, 0, 0, 31, 2, 0, 0, 77, 0, 0, 0, 215, 17, 0, 0,
		54, 21, 0, 0, 124, 0, 0, 0, 43, 2, 0, 0, 148, 38, 0, 0, 77, 5, 0, 0, 174, 14, 0, 0, 1, 3, 5, 3, 1, 5, 56, 6, 7, 32,
		2, 4, 0, 0, 0, 0, 5, 6, 7, 8, 9, 4, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 142, 2, 0, 0, 143, 25, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 234,
		0, 0, 0}
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &ctx)
	}
}

func BenchmarkDecodeUint8(*testing.B) {
	buffer := []byte{234}
	var num uint8
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeUint8(&num)
	}
}

func BenchmarkBinaryUint8(*testing.B) {
	buffer := []byte{234}
	var num uint8
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeInt8(*testing.B) {
	buffer := []byte{234}
	var num int8
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeInt8(&num)
	}
}

func BenchmarkBinaryInt8(*testing.B) {
	buffer := []byte{234}
	var num int8
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeUint16(*testing.B) {
	buffer := []byte{179, 21}
	var num uint16
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeUint16(&num)
	}
}

func BenchmarkBinaryUint16(*testing.B) {
	buffer := []byte{179, 21}
	var num uint16
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeInt16(*testing.B) {
	buffer := []byte{179, 221}
	var num int16
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeInt16(&num)
	}
}

func BenchmarkBinaryInt16(*testing.B) {
	buffer := []byte{179, 221}
	var num int16
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeUint32(*testing.B) {
	buffer := []byte{179, 21, 56, 234}
	var num uint32
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeUint32(&num)
	}
}

func BenchmarkBinaryUint32(*testing.B) {
	buffer := []byte{179, 21, 56, 234}
	var num uint32
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}
func BenchmarkDecodeInt32(*testing.B) {
	buffer := []byte{179, 21, 56, 234}
	var num int32
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeInt32(&num)
	}
}

func BenchmarkBinaryInt32(*testing.B) {
	buffer := []byte{179, 21, 56, 234}
	var num int32
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeUint64(*testing.B) {
	buffer := []byte{179, 21, 56, 234, 45, 65, 234, 255}
	var num uint64
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeUint64(&num)
	}
}

func BenchmarkBinaryUint64(*testing.B) {
	buffer := []byte{179, 21, 56, 234, 45, 65, 234, 255}
	var num uint64
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeInt64(*testing.B) {
	buffer := []byte{179, 21, 56, 234, 45, 65, 234, 255}
	var num int64
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeInt64(&num)
	}
}

func BenchmarkBinaryInt64(*testing.B) {
	buffer := []byte{179, 21, 56, 234, 45, 65, 234, 255}
	var num int64
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeBool(*testing.B) {
	buffer := []byte{1}
	var num bool
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeBool(&num)
	}
}
func BenchmarkBinaryBool(*testing.B) {
	buffer := []byte{1}
	var num bool
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeSlimCred(*testing.B) {
	/*
		s := bufferdecoder.SlimCred{
			Uid:            12,
			Gid:            34,
			Suid:           56,
			Sgid:           78,
			Euid:           91,
			Egid:           234,
			Fsuid:          654,
			Fsgid:          765,
			UserNamespace:  7654,
			SecureBits:     7654,
			CapInheritable: 345,
			CapPermitted:   234,
			CapEffective:   7653,
			CapBounding:    8765,
			CapAmbient:     765423,
		}

		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{12, 0, 0, 0, 34, 0, 0, 0, 56, 0, 0, 0, 78, 0, 0, 0, 91, 0, 0, 0, 234, 0, 0, 0, 142, 2, 0, 0, 253, 2, 0, 0,
		230, 29, 0, 0, 230, 29, 0, 0, 89, 1, 0, 0, 0, 0, 0, 0, 234, 0, 0, 0, 0, 0, 0, 0, 229, 29, 0, 0, 0, 0, 0, 0,
		61, 34, 0, 0, 0, 0, 0, 0, 239, 173, 11, 0, 0, 0, 0, 0}
	var s types.SlimCred
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeSlimCred(&s)
	}
}

func BenchmarkBinarySlimCred(*testing.B) {
	/*
		s := bufferdecoder.SlimCred{
			Uid:            12,
			Gid:            34,
			Suid:           56,
			Sgid:           78,
			Euid:           91,
			Egid:           234,
			Fsuid:          654,
			Fsgid:          765,
			UserNamespace:  7654,
			SecureBits:     7654,
			CapInheritable: 345,
			CapPermitted:   234,
			CapEffective:   7653,
			CapBounding:    8765,
			CapAmbient:     765423,
		}

		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{12, 0, 0, 0, 34, 0, 0, 0, 56, 0, 0, 0, 78, 0, 0, 0, 91, 0, 0, 0, 234, 0, 0, 0, 142, 2, 0, 0, 253, 2, 0, 0,
		230, 29, 0, 0, 230, 29, 0, 0, 89, 1, 0, 0, 0, 0, 0, 0, 234, 0, 0, 0, 0, 0, 0, 0, 229, 29, 0, 0, 0, 0, 0, 0,
		61, 34, 0, 0, 0, 0, 0, 0, 239, 173, 11, 0, 0, 0, 0, 0}
	var s types.SlimCred
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func BenchmarkDecodeChunkMeta(*testing.B) {
	/*
		s := ChunkMeta{
			binType:  1,
			CgroupID: 54,
			Metadata: [24]byte{
				54,
				12,
				54,
				145,
				42,
				72,
				134,
				64,
				125,
				53,
				62,
				62,
				123,
				255,
				123,
				5,
				0,
				32,
				234,
				23,
				42,
				123,
				32,
				2,
			},
			Size: 2,
			Off:  23,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{1, 54, 0, 0, 0, 0, 0, 0, 0, 54, 12, 54, 145, 42, 72, 134, 64, 125, 53, 62, 62, 123, 255, 123, 5, 0, 32, 234,
		23, 42, 123, 32, 2, 2, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0}
	var s types.ChunkMeta
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeChunkMeta(&s)
	}
}
func BenchmarkBinaryChunkMeta(*testing.B) {
	/*
		s := ChunkMeta{
			binType:  1,
			CgroupID: 54,
			Metadata: [24]byte{
				54,
				12,
				54,
				145,
				42,
				72,
				134,
				64,
				125,
				53,
				62,
				62,
				123,
				255,
				123,
				5,
				0,
				32,
				234,
				23,
				42,
				123,
				32,
				2,
			},
			Size: 2,
			Off:  23,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{1, 54, 0, 0, 0, 0, 0, 0, 0, 54, 12, 54, 145, 42, 72, 134, 64, 125, 53, 62, 62, 123, 255, 123, 5, 0, 32, 234,
		23, 42, 123, 32, 2, 2, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0}
	var s types.ChunkMeta
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func BenchmarkDecodeVfsWriteMeta(*testing.B) {
	/*
		s := VfsFileMeta{
			DevID: 24,
			Inode: 3,
			Mode:  255,
			Pid:   0,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/

	buffer := []byte{24, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0}
	var s types.VfsFileMeta
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeVfsFileMeta(&s)
	}
}

func BenchmarkBinaryVfsWriteMeta(*testing.B) {
	/*
		s := VfsFileMeta{
			DevID: 24,
			Inode: 3,
			Mode:  255,
			Pid:   0,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/

	buffer := []byte{24, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0}
	var s types.VfsFileMeta
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func BenchmarkDecodeKernelModuleMeta(*testing.B) {
	/*
		s := KernelModuleMeta{
			DevID: 43,
			Inode: 65,
			Pid:   234,
			Size:  1,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{43, 0, 0, 0, 65, 0, 0, 0, 0, 0, 0, 0, 234, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
	var s types.KernelModuleMeta
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeKernelModuleMeta(&s)
	}
}

func BenchmarkBinaryKernelModuleMeta(*testing.B) {
	/*
		s := KernelModuleMeta{
			DevID: 43,
			Inode: 65,
			Pid:   234,
			Size:  1,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{43, 0, 0, 0, 65, 0, 0, 0, 0, 0, 0, 0, 234, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
	var s types.KernelModuleMeta
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func BenchmarkDecodeMprotectWriteMeta(*testing.B) {
	/*
		s := MprotectWriteMeta{
			Ts: 123,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{123, 0, 0, 0, 0, 0, 0, 0}
	var s types.MprotectWriteMeta
	for i := 0; i < 100; i++ {
		decoder := NewEventDecoder(log, buffer, nil)
		decoder.DecodeMprotectWriteMeta(&s)
	}
}

func BenchmarkBinaryMprotectWriteMeta(*testing.B) {
	/*
		s := MprotectWriteMeta{
			Ts: 123,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{123, 0, 0, 0, 0, 0, 0, 0}
	var s types.MprotectWriteMeta
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func TestPrintUint32IP(t *testing.T) {
	var input uint32 = 3232238339
	ip := PrintUint32IP(input)

	expectedIP := "192.168.11.3"
	assert.Equal(t, expectedIP, ip)
}

func TestPrint16BytesSliceIP(t *testing.T) {
	input := []byte{32, 1, 13, 184, 133, 163, 0, 0, 0, 0, 138, 46, 3, 112, 115, 52}
	ip := Print16BytesSliceIP(input)

	expectedIP := "2001:db8:85a3::8a2e:370:7334"
	assert.Equal(t, expectedIP, ip)
}

type dnsRecord struct {
	dnsType uint32
	name    string
	ip      string
}

type dnsData struct {
	question string
	answers  []dnsRecord
}

var udpDnsData = dnsData{
	question: "orf.at",
	answers: []dnsRecord{
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.142"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.150"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.141"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.4"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.140"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.149"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.139"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.3"},
	},
}
var dnsOverUDP4 = []byte{
	// Payload size
	0xe4, 0x00, 0x00, 0x00,

	// IP header
	0x45, 0x00, 0x00, 0xe4, 0xb4, 0x0c, 0x40, 0x00, 0x3f, 0x11, 0x71, 0x44, 0x0a, 0x60, 0x00, 0x0a,
	0x0a, 0xf4, 0x00, 0x5b,

	// UDP header
	0x00, 0x35, 0xc5, 0x78, 0x00, 0xd0, 0x16, 0x9a,

	// DNS message
	0xc2, 0x3b, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x6f, 0x72, 0x66,
	0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00,
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8e, 0x03, 0x6f,
	0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04,
	0xc2, 0xe8, 0x68, 0x96, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8d, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61,
	0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x04,
	0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e,
	0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8c, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x95, 0x03, 0x6f, 0x72, 0x66,
	0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8,
	0x68, 0x8b, 0x03, 0x6f, 0x72, 0x66, 0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x1e, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x03,
}

var tcpDnsData = dnsData{
	question: "orf.at",
	answers: []dnsRecord{
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.149"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.140"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.139"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.3"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.4"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.142"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.150"},
		{uint32(dnsmessage.TypeA), "orf.at", "194.232.104.141"},
	},
}
var dnsOverTCP4FullMessage = []byte{
	// Payload size
	0xd9, 0x00, 0x00, 0x00,

	// IP header
	0x45, 0x00, 0x00, 0xd9, 0x1f, 0x80, 0x00, 0x00, 0x3e, 0x06, 0x40, 0xca, 0x08, 0x08, 0x08, 0x08,
	0x0a, 0xf4, 0x00, 0xd2,

	// TCP header
	0x00, 0x35, 0x8c, 0xa3, 0x68, 0x44, 0x89, 0x14, 0xf6, 0xbc, 0xee, 0x75, 0x80, 0x18, 0x10, 0x00,
	0xde, 0x52, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x9c, 0x9f, 0xf4, 0x2a, 0xaa, 0xaa, 0x20, 0x0d,

	// DNS length
	0x00, 0xa3,

	// DNS message
	0xbb, 0xcb, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x03, 0x6f, 0x72, 0x66,
	0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x95, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8c, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x03, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x04, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8e, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x96, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8d, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00,
}

// NOTE: both the IP header checksum and TCP checksum are invalid, but since we are not useing them
// anyway, it doesn't matter for the test.
var dnsOverTCP4Partial = []byte{
	// Payload size
	0xc9, 0x00, 0x00, 0x00,

	0x0a, 0xf4, 0x00, 0xd2,

	// TCP header
	0x00, 0x35, 0x8c, 0xa3, 0x68, 0x44, 0x89, 0x14, 0xf6, 0xbc, 0xee, 0x75, 0x80, 0x18, 0x10, 0x00,
	0xde, 0x52, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x9c, 0x9f, 0xf4, 0x2a, 0xaa, 0xaa, 0x20, 0x0d,

	// DNS length
	0x00, 0xa0,

	// DNS message
	0xbb, 0xcb, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x03, 0x6f, 0x72, 0x66,
	0x02, 0x61, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x95, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8c, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8b, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x03, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x04, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8e, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x96, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
	0x3f, 0xd1, 0x00, 0x04, 0xc2, 0xe8, 0x68, 0x8d, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00,
}

func TestDecodeDns(t *testing.T) {
	type testCase struct {
		title       string
		data        []byte
		expectError bool
		expectedDns dnsData
	}

	testCases := []testCase{
		{
			title:       "udp",
			data:        dnsOverUDP4,
			expectedDns: udpDnsData,
		},
		{
			title:       "tcp full message",
			data:        dnsOverTCP4FullMessage,
			expectedDns: tcpDnsData,
		},
		{
			title:       "tcp partial message",
			data:        dnsOverTCP4Partial,
			expectError: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			d := NewEventDecoder(log, test.data, nil)

			result, err := d.ReadProtoDNS()
			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, test.expectedDns.question, result.GetDNSQuestionDomain())
			require.Len(t, result.GetAnswers(), len(test.expectedDns.answers))

			for i, answer := range result.GetAnswers() {
				expectedAnswer := test.expectedDns.answers[i]

				require.Equal(t, expectedAnswer.dnsType, answer.Type)
				require.Equal(t, expectedAnswer.name, answer.Name)
				resIP, _ := netip.AddrFromSlice(answer.Ip)
				require.Equal(t, expectedAnswer.ip, resIP.String())
			}
		})
	}
}
