package nodes

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A speed test measures TCP throughput through one GRE tunnel between the
// Controller and a Node. The Node never opens a port on its own: the
// Controller offers a one-time token in its probe acknowledgment, the Agent
// listens on its inner tunnel address for at most 45 seconds and accepts
// one connection, and the Controller connects through the tunnel.
const (
	speedSeconds   = 5
	speedWait      = 3 * time.Minute
	responderLimit = 45 * time.Second
)

// SpeedTest is the Controller's view of one test. Upload is Controller to
// Node, Download Node to Controller, both in Mbit/s measured by the receiver.
type SpeedTest struct {
	ID       string    `json:"id"`
	Node     string    `json:"node"`
	Tunnel   string    `json:"tunnel"`
	State    string    `json:"state"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Upload   *float64  `json:"upload_mbps,omitempty"`
	Download *float64  `json:"download_mbps,omitempty"`
	Error    string    `json:"error,omitempty"`

	offer     SpeedOffer
	delivered bool
}

func active(t *SpeedTest) bool {
	return t != nil && t.State != "done" && t.State != "failed"
}

// StartSpeedTest queues a test for a Node's tunnel; one test runs at a time.
func (h *Hub) StartSpeedTest(node, tunnel string) (SpeedTest, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expireSpeedLocked()
	if active(h.speed) {
		return SpeedTest{}, problem("busy", "Another speed test is running")
	}
	o, ok := h.probes[node]
	if !ok || h.now().Sub(o.seen) > 3*time.Minute {
		return SpeedTest{}, problem("no_probes", "This node has not sent a tunnel report recently; update it to v1.4.1 or later")
	}
	address := ""
	for _, t := range o.report.Tunnels {
		if t.ID == tunnel {
			address = t.Address
		}
	}
	if address == "" {
		return SpeedTest{}, problem("no_tunnel", "This node does not report that GRE tunnel")
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	t := &SpeedTest{ID: randomID(), Node: node, Tunnel: tunnel, State: "waiting", Created: h.now(), Updated: h.now()}
	t.offer = SpeedOffer{ID: t.ID, Address: address, Port: 20000 + int(binary.BigEndian.Uint16(b[:]))%40000, Token: randomID() + randomID(), Seconds: speedSeconds}
	h.speed = t
	return *t, nil
}

// SpeedTestView returns the current or last test.
func (h *Hub) SpeedTestView(id string) (SpeedTest, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expireSpeedLocked()
	if h.speed == nil || h.speed.ID != id {
		return SpeedTest{}, problem("not_found", "Speed test not found")
	}
	return *h.speed, nil
}

func (h *Hub) expireSpeedLocked() {
	if t := h.speed; active(t) && t.State != "running" && h.now().Sub(t.Created) > speedWait {
		t.State, t.Error, t.Updated = "failed", "The node did not start the test in time", h.now()
	}
}

func (h *Hub) failSpeedLocked(message string) {
	h.speed.State, h.speed.Error, h.speed.Updated = "failed", message, h.now()
}

// speedAckLocked answers a probe post: it delivers a pending offer and
// starts the client once the Agent listens.
func (h *Hub) speedAckLocked(node string, responder *SpeedResponder) probeAck {
	ack := probeAck{Protocol: ProbeProtocol}
	h.expireSpeedLocked()
	t := h.speed
	if !active(t) || t.Node != node {
		return ack
	}
	ack.NextSeconds = 5
	switch {
	case !t.delivered:
		offer := t.offer
		ack.SpeedTest = &offer
		t.delivered, t.State, t.Updated = true, "connecting", h.now()
	case responder != nil && responder.ID == t.ID && responder.State == "failed":
		h.failSpeedLocked("Node: " + responder.Error)
	case responder != nil && responder.ID == t.ID && responder.State == "listening" && t.State == "connecting":
		t.State, t.Updated = "running", h.now()
		go h.runSpeedClient(t.ID, t.offer)
	}
	return ack
}

func (h *Hub) finishSpeed(id string, upload, download float64, failure error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.speed == nil || h.speed.ID != id {
		return
	}
	if failure != nil {
		h.failSpeedLocked(failure.Error())
		return
	}
	h.speed.State, h.speed.Updated = "done", h.now()
	h.speed.Upload, h.speed.Download = &upload, &download
}

func mbps(bytes int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return math.Round(float64(bytes)*8/d.Seconds()/1e4) / 100
}

// runSpeedClient uploads for offer.Seconds, reads the Agent's count, then
// counts the download.
func (h *Hub) runSpeedClient(id string, offer SpeedOffer) {
	upload, download, e := speedClient(context.Background(), offer)
	h.finishSpeed(id, upload, download, e)
}

func speedClient(ctx context.Context, offer SpeedOffer) (float64, float64, error) {
	address := net.JoinHostPort(offer.Address, strconv.Itoa(offer.Port))
	conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if e != nil {
		return 0, 0, fmt.Errorf("could not reach %s through the tunnel; a firewall on the node may block it", address)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(offer.Seconds*2+15) * time.Second))
	if _, e = io.WriteString(conn, offer.Token+"\n"); e != nil {
		return 0, 0, errors.New("the node closed the connection")
	}
	buffer := make([]byte, 64*1024)
	until := time.Now().Add(time.Duration(offer.Seconds) * time.Second)
	for time.Now().Before(until) {
		if _, e = conn.Write(buffer); e != nil {
			return 0, 0, errors.New("upload interrupted")
		}
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	reader := bufio.NewReader(conn)
	line, e := reader.ReadString('\n')
	var received, micros int64
	if e != nil || len(line) > 64 {
		return 0, 0, errors.New("the node did not report the upload")
	}
	if _, e = fmt.Sscanf(strings.TrimSpace(line), "U %d %d", &received, &micros); e != nil {
		return 0, 0, errors.New("the node did not report the upload")
	}
	start := time.Now()
	got, _ := io.Copy(io.Discard, reader)
	return mbps(received, time.Duration(micros)*time.Microsecond), mbps(got, time.Since(start)), nil
}

// responder is the Agent's single-connection speed-test server.
type responder struct {
	mu    sync.Mutex
	state *SpeedResponder
}

func (r *responder) set(s SpeedResponder) {
	r.mu.Lock()
	r.state = &s
	r.mu.Unlock()
}

func (r *responder) get() *SpeedResponder {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == nil {
		return nil
	}
	s := *r.state
	return &s
}

func (r *responder) run(ctx context.Context, offer SpeedOffer) {
	ln, e := net.Listen("tcp", net.JoinHostPort(offer.Address, strconv.Itoa(offer.Port)))
	if e != nil {
		r.set(SpeedResponder{ID: offer.ID, State: "failed", Error: "cannot listen on the tunnel address"})
		return
	}
	defer ln.Close()
	r.set(SpeedResponder{ID: offer.ID, State: "listening"})
	if t, ok := ln.(*net.TCPListener); ok {
		_ = t.SetDeadline(time.Now().Add(responderLimit))
	}
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	conn, e := ln.Accept()
	if e != nil {
		r.set(SpeedResponder{ID: offer.ID, State: "failed", Error: "the Controller did not connect"})
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(offer.Seconds*2+15) * time.Second))
	reader := bufio.NewReaderSize(conn, 64*1024)
	line, e := reader.ReadString('\n')
	if e != nil || len(line) > 80 || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(line)), []byte(offer.Token)) != 1 {
		r.set(SpeedResponder{ID: offer.ID, State: "failed", Error: "invalid token"})
		return
	}
	start := time.Now()
	received, _ := io.Copy(io.Discard, io.LimitReader(reader, 8<<30))
	elapsed := time.Since(start)
	if _, e = fmt.Fprintf(conn, "U %d %d\n", received, elapsed.Microseconds()); e != nil {
		r.set(SpeedResponder{ID: offer.ID, State: "failed", Error: "connection closed"})
		return
	}
	buffer := make([]byte, 64*1024)
	until := time.Now().Add(time.Duration(offer.Seconds) * time.Second)
	for time.Now().Before(until) {
		if _, e = conn.Write(buffer); e != nil {
			break
		}
	}
	r.set(SpeedResponder{ID: offer.ID, State: "done"})
}
