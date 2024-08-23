// This program demonstrates attaching a fentry eBPF program to
// tcp_connect. It prints the command/IPs/ports information
// once the host sent a TCP SYN packet to a destination.
// It supports IPv4 at this example.
//
// Sample output:
//
// examples# go run -exec sudo ./fentry
// 2021/11/06 17:51:15 Comm   Src addr      Port   -> Dest addr        Port
// 2021/11/06 17:51:25 wget   10.0.2.15     49850  -> 142.250.72.228   443
// 2021/11/06 17:51:46 ssh    10.0.2.15     58854  -> 10.0.2.1         22
// 2021/11/06 18:13:15 curl   10.0.2.15     54268  -> 104.21.1.217     80

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf main.c -- -I../headers

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
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

	link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpConnect,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	if err := readTracePipe(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "reading trace pipe: %v\n", err)
		os.Exit(1)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
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
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	}
}
