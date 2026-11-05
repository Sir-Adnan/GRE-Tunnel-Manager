package notify

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxEvents  = 300
	viewEvents = 100
	queueSize  = 128
)

type stateFile struct {
	Settings Settings `json:"settings"`
	Revision uint64   `json:"revision"`
	Events   []Event  `json:"events"`
	Next     uint64   `json:"next"`
}

// View is the panel's notification list, newest first.
type View struct {
	Settings SettingsView `json:"settings"`
	Revision uint64       `json:"revision"`
	Unread   int          `json:"unread"`
	Events   []Event      `json:"events"`
	// Kinds lists every kind the settings can select.
	Kinds []string `json:"kinds"`
}

// Center is safe for concurrent use. Path "" keeps everything in memory.
type Center struct {
	mu    sync.Mutex
	path  string
	data  stateFile
	queue chan uint64
	quiet map[string]bool
	// Host labels external messages.
	Host string
}

func New() *Center {
	return &Center{data: stateFile{Settings: DefaultSettings(), Events: []Event{}, Next: 1}, queue: make(chan uint64, queueSize)}
}

func Open(path string) (*Center, error) {
	c := New()
	c.path = path
	c.Host, _ = os.Hostname()
	data, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return c, nil
	}
	if e != nil {
		return nil, e
	}
	var s stateFile
	if e = json.Unmarshal(data, &s); e != nil {
		return nil, e
	}
	s.Settings = s.Settings.normalized()
	if s.Events == nil {
		s.Events = []Event{}
	}
	if s.Next == 0 {
		s.Next = 1
	}
	// Deliveries interrupted by a restart are not retried.
	for i := range s.Events {
		if s.Events[i].Delivery == DeliveryPending {
			s.Events[i].Delivery = DeliveryFailed
		}
	}
	c.data = s
	return c, nil
}

func (c *Center) saveLocked() error {
	if c.path == "" {
		return nil
	}
	data, e := json.Marshal(c.data)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(c.path), 0700); e != nil {
		return e
	}
	temp := c.path + ".tmp"
	if e = os.WriteFile(temp, data, 0600); e != nil {
		return e
	}
	return os.Rename(temp, c.path)
}

// Emit records an event and queues it for external channels when its kind
// is selected. It never blocks: a full queue marks the event failed.
// SetQuiet lists owners whose events stay in the panel and are never sent
// to the webhook or Telegram (health settings own the list).
func (c *Center) SetQuiet(owners []string) {
	if c == nil {
		return
	}
	set := make(map[string]bool, len(owners))
	for _, o := range owners {
		set[o] = true
	}
	c.mu.Lock()
	c.quiet = set
	c.mu.Unlock()
}

func (c *Center) Emit(e Event) Event {
	if c == nil {
		return e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = severityOf(e.Kind)
	}
	e.ID, e.Read, e.Delivery = c.data.Next, false, ""
	e.Name, e.Detail = clip(e.Name, 80), clip(e.Detail, 300)
	if len(e.Args) > 8 {
		e.Args = nil
	}
	for k, v := range e.Args {
		e.Args[k] = clip(v, 200)
	}
	c.data.Next++
	if c.data.Settings.external(e.Kind) && (e.Owner == "" || !c.quiet[e.Owner]) {
		e.Delivery = DeliveryPending
		select {
		case c.queue <- e.ID:
		default:
			e.Delivery = DeliveryFailed
		}
	}
	c.data.Events = append(c.data.Events, e)
	if n := len(c.data.Events); n > maxEvents {
		c.data.Events = append([]Event(nil), c.data.Events[n-maxEvents:]...)
	}
	_ = c.saveLocked()
	return e
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (c *Center) View() View {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := View{Settings: c.data.Settings.view(), Revision: c.data.Revision, Events: []Event{}, Kinds: Kinds}
	for i := len(c.data.Events) - 1; i >= 0; i-- {
		e := c.data.Events[i]
		if !e.Read {
			v.Unread++
		}
		if len(v.Events) < viewEvents {
			v.Events = append(v.Events, e)
		}
	}
	return v
}

// MarkRead marks the listed events, or every event with all.
func (c *Center) MarkRead(ids []uint64, all bool) error {
	if len(ids) > viewEvents {
		return errors.New("too many notifications")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	set := map[uint64]bool{}
	for _, id := range ids {
		set[id] = true
	}
	for i := range c.data.Events {
		if all || set[c.data.Events[i].ID] {
			c.data.Events[i].Read = true
		}
	}
	return c.saveLocked()
}

func (c *Center) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.Events = []Event{}
	return c.saveLocked()
}

// Configure replaces the settings; empty secrets keep the stored ones.
func (c *Center) Configure(in Settings, revision uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if revision != c.data.Revision {
		return errors.New("notification settings changed; reload and try again")
	}
	next := merge(c.data.Settings, in)
	if e := next.Validate(); e != nil {
		return e
	}
	c.data.Settings = next
	c.data.Revision++
	return c.saveLocked()
}

func (c *Center) settings() Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.Settings
}

func (c *Center) event(id uint64) (Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.data.Events {
		if e.ID == id {
			return e, true
		}
	}
	return Event{}, false
}

func (c *Center) setDelivery(id uint64, state string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.data.Events {
		if c.data.Events[i].ID == id {
			c.data.Events[i].Delivery = state
			_ = c.saveLocked()
			return
		}
	}
}
