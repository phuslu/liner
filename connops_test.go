package main

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConnOpsSetTcpNotsentLowatOnce(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tc, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("accepted connection type = %T, want *net.TCPConn", conn)
	}

	ops := &ConnOps{tc: tc}
	var appliedCount atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if applied, _ := ops.SetTcpNotsentLowatOnce(128 * 1024); applied {
				appliedCount.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := appliedCount.Load(); got != 1 {
		t.Fatalf("SetTcpNotsentLowatOnce applied %d times, want 1", got)
	}
}
