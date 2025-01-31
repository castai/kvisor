//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/castai/kvisor/pkg/ebpftracer/types"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -strip=llvm-strip -target amd64 bpf main.c -- -I../headers -Wno-address-of-packed-member -O2
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -strip=llvm-strip -target arm64 bpf main.c -- -I../headers -Wno-address-of-packed-member -O2

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	attachTracing := func(prog *ebpf.Program) link.Link {
		info, _ := prog.Info()
		fmt.Printf("attaching prog: %v\n", info.Name)
		defer func() {
			fmt.Printf("attached prog: %v\n", info.Name)
		}()
		ln, err := link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
		if err != nil {
			log.Fatalf("prog=%s: %v", prog, err)
		}
		return ln
	}
	_ = attachTracing

	attachTP := func(prog *ebpf.Program, name string) link.Link {
		ln, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    name,
			Program: prog,
		})
		if err != nil {
			log.Fatal(err)
		}
		return ln
	}
	_ = attachTP

	attachKprobe := func(prog *ebpf.Program, name string) link.Link {
		ln, err := link.Kprobe(name, prog, &link.KprobeOptions{})
		if err != nil {
			log.Fatalf("kprobe %s: %v", name, err)
		}
		return ln
	}
	_ = attachKprobe

	cgPath, err := detectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	attachCgroup := func(prog *ebpf.Program, attachType ebpf.AttachType) link.Link {
		info, _ := prog.Info()
		fmt.Printf("attaching prog: %v\n", info.Name)
		defer func() {
			fmt.Printf("attached prog: %v\n", info.Name)
		}()
		ln, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgPath,
			Attach:  attachType,
			Program: prog,
		})
		if err != nil {
			log.Fatal(err)
		}
		return ln
	}
	_ = attachCgroup

	links := []link.Link{
		attachTracing(objs.TraceInetSockSetState),
		attachKprobe(objs.TraceSecuritySkClone, "security_sk_clone"),
		attachCgroup(objs.CgroupSkbIngress, ebpf.AttachCGroupInetIngress),
		attachCgroup(objs.CgroupSkbEgress, ebpf.AttachCGroupInetEgress),
		attachCgroup(objs.CgroupConnect4, ebpf.AttachCGroupInet4Connect),
		attachCgroup(objs.CgroupSockCreate, ebpf.AttachCGroupInetSockCreate),
		attachCgroup(objs.CgroupSockRelease, ebpf.AttachCgroupInetSockRelease),
	}

	defer func() {
		for _, l := range links {
			if l != nil {
				l.Close()
			}
		}
		objs.Close()
	}()

	//go func() {
	//	if err := readTracePipe(ctx); err != nil && !errors.Is(err, context.Canceled) {
	//		fmt.Fprintf(os.Stderr, "reading trace pipe: %v\n", err)
	//		os.Exit(1)
	//	}
	//}()

	go func() {
		readEvents(ctx, rd)
	}()

	select {
	case <-ctx.Done():
		return
	}
}

func readEvents(ctx context.Context, rd *ringbuf.Reader) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		e := ebpfEvent{buffer: record.RawSample}
		if err := e.Decode(); err != nil {
			fmt.Printf("decode event: %v\n", err)
			continue
		}
		fmt.Printf("kind=%-30s proc=%-20s src=%-20s dst=%-20s cookie=%-10d \n",
			e.kind,
			fmt.Sprintf("(%s | %s)", string(e.currComm[:]), string(e.comm[:])),
			e.tuple.Src,
			e.tuple.Dst,
			e.cookie,
		)
	}
}

func readTracePipe(ctx context.Context) error {
	fmt.Println("reading trace pipe")
	tp, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		return err
	}
	defer tp.Close()

	go func() {
		sk := bufio.NewScanner(tp)
		for sk.Scan() {
			fmt.Println(sk.Text())
		}
		fmt.Println("done scanning trace pipe")
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	}
}

func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroupv2 not found, need to mount")
}

type ebpfEvent struct {
	buffer []byte
	cursor int

	kind     ebpfEventKind
	currComm string
	comm     string
	tuple    types.AddrTuple
	cookie   uint64
}

func (e *ebpfEvent) Decode() error {
	var kind uint32
	if err := e.DecodeUint32(&kind); err != nil {
		return fmt.Errorf("decode kind: %w", err)
	}
	e.kind = ebpfEventKind(kind)
	if err := e.DecodeTuple(&e.tuple); err != nil {
		return fmt.Errorf("decode tuple: %w", err)
	}
	if err := e.DecodeUint64(&e.cookie); err != nil {
		return fmt.Errorf("decode cookie: %w", err)
	}

	currComm := [16]byte{}
	if err := e.DecodeBytes(currComm[:], 16); err != nil {
		return fmt.Errorf("decode current comm: %w", err)
	}
	e.currComm = string(bytes.TrimRight(currComm[:], "\x00"))

	comm := [16]byte{}
	if err := e.DecodeBytes(comm[:], 16); err != nil {
		return fmt.Errorf("decode comm: %w", err)
	}
	e.comm = string(bytes.TrimRight(comm[:], "\x00"))

	return nil
}

func (e *ebpfEvent) DecodeTuple(dst *types.AddrTuple) error {
	srcAddr := [16]byte{}
	if err := e.DecodeBytes(srcAddr[:], len(srcAddr)); err != nil {
		return err
	}
	dstAddr := [16]byte{}
	if err := e.DecodeBytes(dstAddr[:], len(dstAddr)); err != nil {
		return err
	}
	var srcPort uint16
	if err := e.DecodeUint16(&srcPort); err != nil {
		return err
	}
	var dstPort uint16
	if err := e.DecodeUint16(&dstPort); err != nil {
		return err
	}
	var family uint16
	if err := e.DecodeUint16(&family); err != nil {
		return err
	}
	dst.Src = addrPort(family, srcAddr, srcPort)
	dst.Dst = addrPort(family, dstAddr, dstPort)
	return nil
}

func (e *ebpfEvent) DecodeBytes(dst []byte, size int) error {
	offset := e.cursor
	bufferLen := len(e.buffer[offset:])
	if bufferLen < size {
		return errors.New("short buffer")
	}
	_ = copy(dst[:], e.buffer[offset:offset+size])
	e.cursor += size
	return nil
}

func (e *ebpfEvent) DecodeUint8(msg *uint8) error {
	readAmount := 1
	offset := e.cursor
	if len(e.buffer[offset:]) < readAmount {
		return errors.New("short buffer")
	}
	*msg = e.buffer[e.cursor]
	e.cursor += readAmount
	return nil
}

func (e *ebpfEvent) DecodeUint16(dst *uint16) error {
	readAmount := 2
	offset := e.cursor
	if len(e.buffer[offset:]) < readAmount {
		return errors.New("short buffer")
	}
	*dst = binary.LittleEndian.Uint16(e.buffer[offset : offset+readAmount])
	e.cursor += readAmount
	return nil
}

func (e *ebpfEvent) DecodeUint32(dst *uint32) error {
	readAmount := 4
	offset := e.cursor
	if len(e.buffer[offset:]) < readAmount {
		return errors.New("short buffer")
	}
	*dst = binary.LittleEndian.Uint32(e.buffer[offset : offset+readAmount])
	e.cursor += readAmount
	return nil
}

func (e *ebpfEvent) DecodeUint64(msg *uint64) error {
	readAmount := 8
	offset := e.cursor
	if len(e.buffer[offset:]) < readAmount {
		return errors.New("short buffer")
	}
	*msg = binary.LittleEndian.Uint64(e.buffer[offset : offset+readAmount])
	e.cursor += readAmount
	return nil
}

func addrPort(family uint16, ip [16]byte, port uint16) netip.AddrPort {
	switch types.SockAddrFamily(family) {
	case types.AF_INET6:
		return netip.AddrPortFrom(netip.AddrFrom16(ip).Unmap(), port)
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]}), port)
}

type ebpfEventKind uint32

func (e ebpfEventKind) String() string {
	switch e {
	case 1:
		return "security_socket_connect"
	case 2:
		return "security_socket_sendmsg"
	case 3:
		return "inet_sock_set_state"
	case 4:
		return "cgroup_skb_egress"
	case 5:
		return "cgroup_skb_ingress"
	case 6:
		return "security_sk_clone"
	case 7:
		return "security_sk_clone_old"
	case 8:
		return "cgroup_sock_create"
	case 9:
		return "cgroup_connectv4"
	case 10:
		return "cgroup_sock_release"
	}
	return strconv.Itoa(int(e))
}
