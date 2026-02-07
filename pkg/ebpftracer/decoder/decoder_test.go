package decoder

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
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

func TestDecodeUint8(t *testing.T) {
	buf := new(bytes.Buffer)
	var expected uint8 = 42
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, b)
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
	d := NewEventDecoder(log, buf.Bytes())
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
	decoder := NewEventDecoder(log, raw)
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
		decoder := NewEventDecoder(log, buffer)
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
		decoder := NewEventDecoder(log, buffer)
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
		decoder := NewEventDecoder(log, buffer)
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
		decoder := NewEventDecoder(log, buffer)
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
		decoder := NewEventDecoder(log, buffer)
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
		decoder := NewEventDecoder(log, buffer)
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
		decoder := NewEventDecoder(log, buffer)
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
		decoder := NewEventDecoder(log, buffer)
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
		decoder := NewEventDecoder(log, buffer)
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
		decoder := NewEventDecoder(log, buffer)
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
	question: "orf.at.",
	answers: []dnsRecord{
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.142"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.150"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.141"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.4"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.140"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.149"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.139"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.3"},
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
	question: "orf.at.",
	answers: []dnsRecord{
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.149"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.140"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.139"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.3"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.4"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.142"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.150"},
		{uint32(dnsmessage.TypeA), "orf.at.", "194.232.104.141"},
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
			d := NewEventDecoder(log, test.data)

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

func TestDecodeContext(t *testing.T) {
	r := require.New(t)

	path := filepath.Join("testdata", "magic_write_event.bin")
	data, err := os.ReadFile(path)
	r.NoError(err)

	var eventCtx types.EventContext

	decoder := NewEventDecoder(log, data)
	err = decoder.DecodeContext(&eventCtx)
	r.NoError(err)

	r.Equal(types.EventContext{
		Ts:              4693384711035,
		StartTime:       4693381625195,
		CgroupID:        11604,
		Pid:             2297,
		Tid:             2297,
		Ppid:            1,
		HostPid:         26269,
		HostTid:         26269,
		HostPpid:        21059,
		NodeHostPid:     26269,
		Uid:             0,
		MntID:           4026533011,
		PidID:           4026533012,
		Comm:            [16]byte{0x74, 0x61, 0x72},
		LeaderStartTime: 4693381625195,
		ParentStartTime: 4361168401687,
		EventID:         718,
		Syscall:         64,
		Retval:          9728,
		ProcessorId:     1,
	}, eventCtx)
}

func TestProcessNameString(t *testing.T) {
	tests := []struct {
		name     string
		value    []byte
		expected string
	}{
		{
			name:     "no null terminator",
			value:    []byte("curl"),
			expected: "curl",
		},
		{
			name:     "truncate at first null terminator",
			value:    []byte{116, 101, 115, 116, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: "test",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, ProcessNameString(test.value))
		})
	}
}

var sshRequestData = []byte{
	// Payload size
	0x5e, 0x00, 0x00, 0x00,

	// IPv4 header
	0x45, 0x10, 0x00, 0x5e, 0xe6, 0x79, 0x40, 0x00,
	0x40, 0x06, 0xcd, 0xac, 0xc0, 0xa8, 0x05, 0x0f,
	0xc0, 0xa8, 0x00, 0x04,

	// TCP
	0xd1, 0xa8, 0x00, 0x16, 0xeb, 0x5d, 0xea, 0xad,
	0x40, 0x9c, 0x9b, 0xa7, 0x80, 0x18, 0x01, 0xf6,
	0xad, 0x09, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
	0xd8, 0x56, 0x33, 0xba, 0x57, 0x4a, 0x2e, 0x6a,

	// SSH Version
	// "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
	0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e, 0x30, 0x2d,
	0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x48, 0x5f,
	0x38, 0x2e, 0x39, 0x70, 0x31, 0x20, 0x55, 0x62,
	0x75, 0x6e, 0x74, 0x75, 0x2d, 0x33, 0x75, 0x62,
	0x75, 0x6e, 0x74, 0x75, 0x30, 0x2e, 0x31, 0x30,
	0x0d, 0x0a,
}

var sshRequestWithouthCommentData = []byte{
	// Payload size
	0x47, 0x00, 0x00, 0x00,

	// IPv4 header
	0x45, 0x10, 0x00, 0x47, 0xe6, 0x79, 0x40, 0x00,
	0x40, 0x06, 0xcd, 0xac, 0xc0, 0xa8, 0x05, 0x0f,
	0xc0, 0xa8, 0x00, 0x04,

	// TCP
	0xd1, 0xa8, 0x00, 0x16, 0xeb, 0x5d, 0xea, 0xad,
	0x40, 0x9c, 0x9b, 0xa7, 0x80, 0x18, 0x01, 0xf6,
	0xad, 0x09, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
	0xd8, 0x56, 0x33, 0xba, 0x57, 0x4a, 0x2e, 0x6a,

	// SSH Version
	// "SSH-2.0-OpenSSH_9.7"
	0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e, 0x30, 0x2d,
	0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x48, 0x5f,
	0x39, 0x2e, 0x37,
}

var sshRequestBorked = []byte{
	// Payload size
	0x38, 0x00, 0x00, 0x00,

	// IPv4 header
	0x45, 0x10, 0x00, 0x38, 0xe6, 0x79, 0x40, 0x00,
	0x40, 0x06, 0xcd, 0xac, 0xc0, 0xa8, 0x05, 0x0f,
	0xc0, 0xa8, 0x00, 0x04,

	// TCP
	0xd1, 0xa8, 0x00, 0x16, 0xeb, 0x5d, 0xea, 0xad,
	0x40, 0x9c, 0x9b, 0xa7, 0x80, 0x18, 0x01, 0xf6,
	0xad, 0x09, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
	0xd8, 0x56, 0x33, 0xba, 0x57, 0x4a, 0x2e, 0x6a,

	// SSH
	// "SSHH"
	0x53, 0x53, 0x48, 0x48,
}

func TestDecodeSSH(t *testing.T) {
	type testCase struct {
		title       string
		data        []byte
		expected    *types.ProtoSSH
		expectError error
	}

	testCases := []testCase{
		{
			title: "should full ssh version",
			data:  sshRequestData,
			expected: &types.ProtoSSH{
				Version:  "SSH-2.0-OpenSSH_8.9p1",
				Comments: "Ubuntu-3ubuntu0.10",
			},
		},
		{
			title: "should ignore missing comments",
			data:  sshRequestWithouthCommentData,
			expected: &types.ProtoSSH{
				Version: "SSH-2.0-OpenSSH_9.7",
			},
		},
		{
			title:       "should ignore borked packet",
			data:        sshRequestBorked,
			expectError: ErrWrongSSHVersionPrefix,
		},
	}

	log := logging.New(&logging.Config{})

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			d := NewEventDecoder(log, test.data)

			result, err := d.ReadProtoSSH()
			if test.expectError != nil {
				require.ErrorIs(t, err, test.expectError)
				return
			}

			require.NoError(t, err)

			r.Equal(test.expected.Comments, result.Comments)
			r.Equal(test.expected.Version, result.Version)
		})
	}
}
