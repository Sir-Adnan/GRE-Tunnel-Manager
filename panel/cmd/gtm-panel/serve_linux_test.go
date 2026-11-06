package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestHTTPPublicServiceSurvivesReloadSignal(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, address, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }), "", "")
	}()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	ready := false
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		r, e := client.Get("http://" + address)
		if e == nil {
			_ = r.Body.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("HTTP fixture did not start")
	}
	process, e := os.FindProcess(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	if e = process.Signal(syscall.SIGHUP); e != nil {
		t.Fatal(e)
	}
	r, e := client.Get("http://" + address)
	if e != nil {
		t.Fatal("HTTP reload terminated service", e)
	}
	_ = r.Body.Close()
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP fixture did not stop")
	}
}
