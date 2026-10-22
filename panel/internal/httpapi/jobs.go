package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

type Job struct {
	ID      string          `json:"id"`
	Action  string          `json:"action"`
	State   string          `json:"state"`
	Started time.Time       `json:"started"`
	Ended   *time.Time      `json:"ended,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
}
type Jobs struct {
	mu      sync.Mutex
	items   map[string]Job
	running bool
	client  control.Client
	ctx     context.Context
}

func NewJobs(ctx context.Context, c control.Client) *Jobs {
	return &Jobs{items: map[string]Job{}, client: c, ctx: ctx}
}
func (j *Jobs) Start(request control.Request) (Job, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.running {
		return Job{}, errors.New("another operation is running; wait for it to finish")
	}
	for id, job := range j.items {
		if job.Ended != nil && time.Since(*job.Ended) > time.Hour {
			delete(j.items, id)
		}
	}
	if len(j.items) >= 32 {
		oldest := ""
		for id, job := range j.items {
			if oldest == "" || job.Started.Before(j.items[oldest].Started) {
				oldest = id
			}
		}
		delete(j.items, oldest)
	}
	job := Job{ID: auth.Random(), Action: request.Action, State: "running", Started: time.Now().UTC()}
	j.items[job.ID] = job
	j.running = true
	go func() {
		ctx, cancel := context.WithTimeout(j.ctx, 10*time.Minute)
		defer cancel()
		result, e := j.client.Do(ctx, request)
		now := time.Now().UTC()
		j.mu.Lock()
		defer j.mu.Unlock()
		completed := j.items[job.ID]
		completed.Ended = &now
		completed.State = "completed"
		completed.Result = result
		if e != nil {
			completed.State = "failed"
			completed.Error = e.Error()
		}
		j.items[job.ID] = completed
		j.running = false
	}()
	return job, nil
}
func (j *Jobs) Get(id string) (Job, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	v, ok := j.items[id]
	return v, ok
}
