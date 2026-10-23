// The broker listens only on a filesystem-protected Unix socket. The public
// HTTP process runs as grepanel and never receives a shell or arbitrary argv API.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Broker struct {
	Manager      *Manager
	ReadOnly     bool
	AgentTraffic bool
	Nodes        *NodeExecutor
	mu           sync.Mutex
}
type Reply struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/control" || r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 131072)
	var request Request
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		http.Error(w, "one request required", 400)
		return
	}
	trafficAllowed := b.AgentTraffic && (request.Action == "metrics" || request.Action == "metrics-configure")
	if (request.Action == "node-task" && (b.Nodes == nil || request.NodeTask == nil)) || (b.ReadOnly && request.Action != "inventory" && request.Action != "capabilities" && request.Action != "node-task" && !trafficAllowed) {
		http.Error(w, "read-only agent broker", http.StatusForbidden)
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	operationContext := r.Context()
	if request.Action != "inventory" && request.Action != "metrics" && request.Action != "metrics-history" && request.Action != "capabilities" && request.Action != "configuration" && request.Action != "configuration-review" {
		// A browser disconnect/public-service restart must not kill an in-flight
		// network transaction. The broker owns its independent bounded lifetime.
		var cancel context.CancelFunc
		operationContext, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
	}
	var result any
	var e error
	if request.Action == "node-task" {
		result, e = b.Nodes.Execute(operationContext, *request.NodeTask)
	} else {
		result, e = b.Manager.Execute(operationContext, request)
	}
	auditedError := e
	if r, ok := result.(NodeResult); ok && oneOf(r.State, "failed", "unknown") {
		auditedError = errors.New("node task incomplete")
	}
	if auditError := audit(request, auditedError); auditError != nil {
		log.Printf("panel audit write failed: %v", auditError)
	}
	reply := Reply{}
	if e != nil {
		reply.Error = e.Error()
	} else {
		reply.Data, _ = json.Marshal(result)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reply)
}
func (b *Broker) Listen(ctx context.Context, socket string) error {
	if b.Nodes != nil {
		if e := os.MkdirAll(b.Nodes.Directory, 0700); e != nil {
			return e
		}
		lease, e := nodeLease(filepath.Join(b.Nodes.Directory, "broker.lock"))
		if e != nil {
			return e
		}
		defer lease.Close()
		if e = b.Nodes.Recover(ctx); e != nil {
			return e
		}
	}
	if e := os.MkdirAll(filepath.Dir(socket), 0750); e != nil {
		return e
	}
	if info, e := os.Lstat(socket); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("broker path is not a socket")
		}
		conn, e := net.DialTimeout("unix", socket, time.Second)
		if e == nil {
			conn.Close()
			return errors.New("broker already running")
		}
		if e = os.Remove(socket); e != nil {
			return e
		}
	}
	listener, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer listener.Close()
	defer os.Remove(socket)
	if e = os.Chmod(socket, 0660); e != nil {
		return e
	}
	server := &http.Server{Handler: b, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 12 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan struct{})
	shutdownDone := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
			defer cancel()
			server.Shutdown(shutdown)
			close(shutdownDone)
		case <-done:
		}
	}()
	if b.Manager.Metrics != nil {
		go b.monitor(ctx, done)
	}
	if b.Nodes != nil {
		go b.monitorNodes(ctx, done)
	}
	e = server.Serve(listener)
	if errors.Is(e, http.ErrServerClosed) {
		<-shutdownDone
		return nil
	}
	return e
}
func (b *Broker) monitorNodes(ctx context.Context, done <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	failed := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-t.C:
			b.mu.Lock()
			c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			e := b.Nodes.Recover(c)
			cancel()
			b.mu.Unlock()
			if e != nil && !failed {
				log.Print("node lease recovery failed; inspect the private broker journal")
			}
			failed = e != nil
		}
	}
}
func (b *Broker) monitor(ctx context.Context, done <-chan struct{}) {
	// No inventory scans, subprocesses or metrics writes while disabled.
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	elapsed := 3600
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-timer.C:
			if !b.Manager.Metrics.Enabled() {
				elapsed = 3600
				continue
			}
			elapsed++
			if elapsed < b.Manager.Metrics.Interval() {
				continue
			}
			elapsed = 0
			sampleCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			b.mu.Lock()
			inventory, e := b.Manager.Inventory(sampleCtx)
			if e == nil {
				_ = b.Manager.Metrics.Tick(sampleCtx, inventory)
			}
			b.mu.Unlock()
			cancel()
		}
	}
}

type Client interface {
	Do(context.Context, Request) (json.RawMessage, error)
}
type UnixClient struct{ http *http.Client }

func NewUnixClient(socket string) *UnixClient {
	return &UnixClient{http: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, Timeout: 11 * time.Minute}}
}
func (c *UnixClient) Do(ctx context.Context, request Request) (json.RawMessage, error) {
	reader, writer := io.Pipe()
	go func() { e := json.NewEncoder(writer).Encode(request); writer.CloseWithError(e) }()
	defer reader.Close()
	req, e := http.NewRequestWithContext(ctx, "POST", "http://broker/control", reader)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := c.http.Do(req)
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("broker returned %d", response.StatusCode)
	}
	var reply Reply
	if e = json.NewDecoder(io.LimitReader(response.Body, 1048576)).Decode(&reply); e != nil {
		return nil, e
	}
	if reply.Error != "" {
		return nil, errors.New(reply.Error)
	}
	return reply.Data, nil
}
