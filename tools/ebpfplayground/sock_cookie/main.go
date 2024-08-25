package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -cc clang-14 -strip=llvm-strip -target amd64 bpf main.c -- -I../headers

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

	attach := func(prog *ebpf.Program) link.Link {
		info, _ := prog.Info()
		fmt.Printf("attaching prog: %v\n", info.Name)
		defer func() {
			fmt.Printf("attached prog: %v\n", info.Name)
		}()
		ln, err := link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
		if err != nil {
			log.Fatal(err)
		}
		return ln
	}

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

	cgPath, err := detectCgroupPath()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("cgPath", cgPath)
	ff, err := os.Open(cgPath)
	if err != nil {
		log.Fatal(err)
	}
	ff.Close()

	attachCgroupSKB := func(prog *ebpf.Program, attachType ebpf.AttachType) link.Link {
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
	_ = attachCgroupSKB

	links := []link.Link{
		attach(objs.SecuritySocketConnect),
		attach(objs.SecuritySocketSendmsg),
		//attach(objs.SecuritySocketRecvmsg),
		attach(objs.SecuritySkClone),
		attach(objs.TraceInetSockSetState),
		//attachCgroupSKB(objs.CgroupSkbIngress, ebpf.AttachCGroupInetIngress),
		//attachCgroupSKB(objs.CgroupSkbEgress, ebpf.AttachCGroupInetEgress),
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

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

func readEvents(ctx context.Context, rd *ringbuf.Reader) {
	var event bpfEvent
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

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		var kind string
		switch event.Kind {
		case 1:
			kind = "security_socket_connect"
		case 2:
			kind = "security_socket_sendmsg"
		case 3:
			kind = "inet_sock_set_state"
		}
		fmt.Printf("kind=%s proc=%s src=%s:%d dst=%s:%d cookie=%d\n", kind, string(event.Comm[:]), intToIP(event.Saddr), event.Sport, intToIP(event.Daddr), event.Dport, event.Cookie)
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
