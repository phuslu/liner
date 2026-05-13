package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestTunTCPIdleTimerClosesIdleConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, stop := tunStartTCPIdleTimer(20*time.Millisecond, server)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := client.Read(b[:])
		errc <- err
	}()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected idle timer to close connection")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("idle timer did not close connection")
	}
}

func TestTunCopyConnWithActivityKeepsIdleTimerAlive(t *testing.T) {
	localClient, localServer := net.Pipe()
	remoteServer, remoteClient := net.Pipe()
	defer localClient.Close()
	defer localServer.Close()
	defer remoteServer.Close()
	defer remoteClient.Close()

	touch, stop := tunStartTCPIdleTimer(80*time.Millisecond, localServer, remoteServer)
	defer stop()

	done := make(chan struct{})
	go func() {
		tunCopyConnWithActivity(remoteServer, localServer, touch)
		close(done)
	}()

	for i := range 5 {
		if err := localClient.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := localClient.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("write %d failed before idle timeout: %v", i, err)
		}
		if err := remoteClient.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if _, err := io.ReadFull(remoteClient, b[:]); err != nil {
			t.Fatalf("read %d failed before idle timeout: %v", i, err)
		}
		if b[0] != byte(i) {
			t.Fatalf("read %d got %d", i, b[0])
		}
		time.Sleep(30 * time.Millisecond)
	}

	localClient.Close()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("copy did not stop after source close")
	}
}
