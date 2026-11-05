package nodes

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

func TestSpeedResponderAndClientMeasureBothDirections(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	offer := SpeedOffer{ID: strings.Repeat("a", 32), Address: "127.0.0.1", Port: port, Token: strings.Repeat("b", 64), Seconds: 1}
	r := &responder{}
	go r.run(context.Background(), offer)
	deadline := time.Now().Add(2 * time.Second)
	for s := r.get(); s == nil || s.State != "listening"; s = r.get() {
		if time.Now().After(deadline) {
			t.Fatal("responder did not listen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	upload, download, e := speedClient(context.Background(), offer)
	if e != nil || upload <= 0 || download <= 0 {
		t.Fatalf("upload %v download %v err %v", upload, download, e)
	}
	for s := r.get(); s.State != "done"; s = r.get() {
		if time.Now().After(deadline.Add(5 * time.Second)) {
			t.Fatalf("state = %+v", s)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A wrong token is refused before any data moves.
	go r.run(context.Background(), offer)
	time.Sleep(100 * time.Millisecond)
	bad := offer
	bad.Token = strings.Repeat("c", 64)
	if _, _, e = speedClient(context.Background(), bad); e == nil {
		t.Fatal("wrong token measured")
	}
}

func TestProbeContractsAreBounded(t *testing.T) {
	good := SpeedOffer{ID: strings.Repeat("a", 32), Address: "10.0.1.2", Port: 30000, Token: strings.Repeat("b", 64), Seconds: 5}
	if good.validate() != nil {
		t.Fatal("valid offer refused")
	}
	for _, bad := range []SpeedOffer{{ID: good.ID, Address: "8.8.8.8", Port: 30000, Token: good.Token, Seconds: 5}, {ID: good.ID, Address: "10.0.1.2", Port: 22, Token: good.Token, Seconds: 5}, {ID: good.ID, Address: "10.0.1.2", Port: 30000, Token: "x", Seconds: 5}, {ID: good.ID, Address: "10.0.1.2", Port: 30000, Token: good.Token, Seconds: 60}} {
		if bad.validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	tunnel := control.ProbeTunnel{ID: "gre-tun-1", Remote: "198.51.100.1", Local: "203.0.113.1", Address: "10.0.1.1", Peer: "10.0.1.2"}
	s := ProbeSideband{Protocol: ProbeProtocol, Report: control.ProbeReport{Time: time.Now(), Tunnels: []control.ProbeTunnel{tunnel}}}
	if s.validate() != nil {
		t.Fatal("valid sideband refused")
	}
	tunnel.ID = "eth0"
	s.Report.Tunnels = []control.ProbeTunnel{tunnel}
	if s.validate() == nil {
		t.Fatal("bad tunnel accepted")
	}
}
