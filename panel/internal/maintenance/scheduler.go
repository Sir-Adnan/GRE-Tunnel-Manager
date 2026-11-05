package maintenance

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
	// Servers without a zoneinfo package still resolve the configured zone.
	_ "time/tzdata"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
)

const (
	// grace is how late a scheduled run may start (panel restart, slow tick)
	// before it is recorded as missed instead of running at an unexpected time.
	grace        = 10 * time.Minute
	maxHistory   = 1000
	maxFileBytes = 8 * 1024 * 1024

	ResultOK        = "ok"
	ResultFailed    = "failed"
	ResultSkipped   = "skipped"
	ResultDryRun    = "dry-run"
	ResultCancelled = "cancelled"
	ResultRebooting = "rebooting"
)

type Settings struct {
	Enabled  bool   `json:"enabled"`
	Timezone string `json:"timezone"`
}

func DefaultSettings() Settings { return Settings{Timezone: "Asia/Tehran"} }

// Pending is a fired run that waits for its notice countdown or quiet traffic.
type Pending struct {
	Reason   string    `json:"reason"`
	Detail   string    `json:"detail,omitempty"`
	Owners   []string  `json:"owners"`
	Since    time.Time `json:"since"`
	RunAt    time.Time `json:"run_at"`
	Deadline time.Time `json:"deadline,omitzero"`
	Manual   bool      `json:"manual,omitempty"`
}

type PlanState struct {
	Next       *time.Time           `json:"next,omitempty"`
	Last       *time.Time           `json:"last,omitempty"`
	LastResult string               `json:"last_result,omitempty"`
	Day        string               `json:"day,omitempty"`
	RunsToday  int                  `json:"runs_today"`
	Pending    *Pending             `json:"pending,omitempty"`
	Since      map[string]time.Time `json:"condition_since,omitempty"`
	// Note explains why a health plan is waiting; it is not persisted history.
	Note string `json:"note,omitempty"`
}

type Entry struct {
	ID        int64     `json:"id"`
	Plan      string    `json:"plan"`
	PlanName  string    `json:"plan_name"`
	Action    string    `json:"action"`
	Owner     string    `json:"owner,omitempty"`
	OwnerName string    `json:"owner_name,omitempty"`
	Engine    string    `json:"engine,omitempty"`
	Reason    string    `json:"reason"`
	Started   time.Time `json:"started"`
	Ended     time.Time `json:"ended"`
	Result    string    `json:"result"`
	Message   string    `json:"message,omitempty"`
}

// Run is a decision to act now.
type Run struct {
	Plan   Plan    `json:"plan"`
	Owners []Owner `json:"owners"`
	Reason string  `json:"reason"`
	Detail string  `json:"detail,omitempty"`
}

// Env is what scheduling needs to know about the server.
type Env interface {
	Owners() []Owner
	Uptime() time.Duration
	// Throughput returns current host traffic in Mbit/s.
	Throughput() (float64, bool)
	HealthEnabled() bool
	// Health reports owner probe state: known, any target down, mean RTT ms.
	Health(owner string) (known, down bool, latency float64)
}

type state struct {
	Settings  Settings              `json:"settings"`
	Revision  uint64                `json:"revision"`
	Plans     []Plan                `json:"plans"`
	States    map[string]*PlanState `json:"states"`
	History   []Entry               `json:"history"`
	NextEntry int64                 `json:"next_entry"`
}

type Scheduler struct {
	mu    sync.Mutex
	path  string
	data  state
	loc   *time.Location
	dirty bool
}

func New() *Scheduler {
	s := &Scheduler{data: state{Settings: DefaultSettings()}}
	s.init()
	return s
}

func Open(path string) (*Scheduler, error) {
	s := New()
	s.path = path
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return nil, errors.New("maintenance state must be a regular file")
	}
	f, e := os.Open(path)
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return nil, e
	}
	data, e := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	_ = f.Close()
	if e != nil {
		return nil, e
	}
	if len(data) > maxFileBytes {
		return nil, errors.New("maintenance state exceeds size limit")
	}
	if e = json.Unmarshal(data, &s.data); e != nil {
		return nil, e
	}
	for i := range s.data.Plans {
		s.data.Plans[i].normalize()
		if e = s.data.Plans[i].Validate(); e != nil {
			return nil, fmt.Errorf("maintenance plan %s: %w", s.data.Plans[i].ID, e)
		}
	}
	s.init()
	return s, nil
}

func (s *Scheduler) init() {
	if s.data.States == nil {
		s.data.States = map[string]*PlanState{}
	}
	if s.data.Plans == nil {
		s.data.Plans = []Plan{}
	}
	if s.data.History == nil {
		s.data.History = []Entry{}
	}
	loc, e := time.LoadLocation(s.data.Settings.Timezone)
	if e != nil {
		loc = time.UTC
	}
	s.loc = loc
}

func (s *Scheduler) Location() *time.Location {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loc
}

func (s *Scheduler) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Settings
}

func (s *Scheduler) checkRevision(revision uint64) error {
	if revision != s.data.Revision {
		return errors.New("maintenance plans changed; refresh and try again")
	}
	return nil
}

func (s *Scheduler) commit() error {
	s.data.Revision++
	return s.saveLocked()
}

func (s *Scheduler) saveLocked() error {
	s.dirty = false
	if s.path == "" {
		return nil
	}
	if e := os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	return config.Save(s.path, s.data, 0600)
}

func (s *Scheduler) Configure(settings Settings, revision uint64) error {
	loc, e := time.LoadLocation(settings.Timezone)
	if settings.Timezone == "" || e != nil {
		return errors.New("unknown time zone")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e = s.checkRevision(revision); e != nil {
		return e
	}
	if s.data.Settings.Timezone != settings.Timezone {
		for _, st := range s.data.States {
			st.Next = nil
		}
	}
	s.data.Settings, s.loc = settings, loc
	return s.commit()
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "m-" + hex.EncodeToString(b)
}

// Save creates (empty ID) or replaces a plan and returns the stored copy.
func (s *Scheduler) Save(now time.Time, p Plan, revision uint64) (Plan, error) {
	p.normalize()
	if e := p.Validate(); e != nil {
		return Plan{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.checkRevision(revision); e != nil {
		return Plan{}, e
	}
	index := slices.IndexFunc(s.data.Plans, func(x Plan) bool { return x.ID == p.ID })
	if p.ID == "" {
		if len(s.data.Plans) >= MaxPlans {
			return Plan{}, fmt.Errorf("at most %d maintenance plans", MaxPlans)
		}
		p.ID, p.Created = newID(), now.UTC()
		s.data.Plans = append(s.data.Plans, p)
	} else if index < 0 {
		return Plan{}, errors.New("plan not found; refresh and try again")
	} else {
		p.Created = s.data.Plans[index].Created
		s.data.Plans[index] = p
	}
	st := s.planState(p.ID)
	st.Next, st.Pending, st.Since, st.Note = nil, nil, nil, ""
	return p, s.commit()
}

func (s *Scheduler) Delete(id string, revision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.checkRevision(revision); e != nil {
		return e
	}
	index := slices.IndexFunc(s.data.Plans, func(x Plan) bool { return x.ID == id })
	if index < 0 {
		return errors.New("plan not found; refresh and try again")
	}
	s.data.Plans = slices.Delete(s.data.Plans, index, index+1)
	delete(s.data.States, id)
	return s.commit()
}

// Queue asks the next evaluation to run a plan now, without its guards.
func (s *Scheduler) Queue(now time.Time, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plan(id)
	if !ok {
		return errors.New("plan not found; refresh and try again")
	}
	st := s.planState(p.ID)
	if st.Pending != nil {
		return errors.New("this plan already has a pending run")
	}
	st.Pending = &Pending{Reason: "manual", Owners: append([]string{}, p.Scope...), Since: now, RunAt: now, Manual: true}
	return s.saveLocked()
}

// Cancel drops a pending run and records it.
func (s *Scheduler) Cancel(now time.Time, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plan(id)
	st := s.data.States[id]
	if !ok || st == nil || st.Pending == nil {
		return errors.New("nothing is pending for this plan")
	}
	s.record(Entry{Plan: p.ID, PlanName: p.Name, Action: p.Action, Reason: st.Pending.Reason, Started: now, Ended: now, Result: ResultCancelled, Message: "Cancelled before it started."})
	st.Pending = nil
	return s.saveLocked()
}

func (s *Scheduler) plan(id string) (Plan, bool) {
	for _, p := range s.data.Plans {
		if p.ID == id {
			return p, true
		}
	}
	return Plan{}, false
}

func (s *Scheduler) planState(id string) *PlanState {
	st := s.data.States[id]
	if st == nil {
		st = &PlanState{}
		s.data.States[id] = st
	}
	return st
}

func (s *Scheduler) record(e Entry) {
	s.data.NextEntry++
	e.ID = s.data.NextEntry
	s.data.History = append(s.data.History, e)
	if extra := len(s.data.History) - maxHistory; extra > 0 {
		s.data.History = append([]Entry(nil), s.data.History[extra:]...)
	}
	s.dirty = true
}

// Finish records the entries of a completed run and persists them.
func (s *Scheduler) Finish(run Run, entries []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := ResultOK
	for _, e := range entries {
		e.Plan, e.PlanName, e.Action = run.Plan.ID, run.Plan.Name, run.Plan.Action
		if e.Reason == "" {
			e.Reason = run.Reason
		}
		s.record(e)
		switch {
		case e.Result == ResultFailed:
			result = ResultFailed
		case result == ResultOK && e.Result != ResultOK:
			result = e.Result
		}
	}
	if st := s.data.States[run.Plan.ID]; st != nil {
		st.LastResult = result
	}
	return s.saveLocked()
}

// ResolveReboots completes "rebooting" entries recorded before bootTime.
func (s *Scheduler) ResolveReboots(bootTime time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for i := range s.data.History {
		e := &s.data.History[i]
		if e.Result == ResultRebooting && e.Started.Before(bootTime) {
			e.Result, e.Ended = ResultOK, bootTime
			e.Message = "Server restarted and the panel is back."
			changed = true
			for id, st := range s.data.States {
				if id == e.Plan && st.LastResult == ResultRebooting {
					st.LastResult = ResultOK
				}
			}
		}
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}

func (s *Scheduler) skip(p Plan, now time.Time, reason, message string) {
	s.record(Entry{Plan: p.ID, PlanName: p.Name, Action: p.Action, Reason: reason, Started: now, Ended: now, Result: ResultSkipped, Message: message})
	if st := s.data.States[p.ID]; st != nil {
		st.LastResult = ResultSkipped
	}
}

// targets resolves a plan's scope against current owners.
func targets(p Plan, owners []Owner, only []string) []Owner {
	out := []Owner{}
	if p.Action == ActionReboot {
		return out
	}
	for _, o := range owners {
		if !Applies(p.Action, o.Engine) {
			continue
		}
		if len(only) > 0 && !slices.Contains(only, o.ID) {
			continue
		}
		if len(only) == 0 && len(p.Scope) > 0 && !slices.Contains(p.Scope, o.ID) {
			continue
		}
		out = append(out, o)
	}
	return out
}

// blocked returns why guards stop a scheduled run now ("" = allowed).
func (s *Scheduler) blocked(p Plan, st *PlanState, now time.Time, env Env) string {
	g := p.Guards
	switch {
	case st.Last != nil && g.Cooldown > 0 && now.Before(st.Last.Add(time.Duration(g.Cooldown)*time.Minute)):
		return "Cooldown since the previous run has not ended."
	case st.RunsToday >= g.MaxPerDay:
		return "Daily run limit reached."
	case p.Action == ActionReboot && g.MinUptime > 0 && env.Uptime() < time.Duration(g.MinUptime)*time.Minute:
		return "Server started recently; reboot loop guard."
	}
	return ""
}

// Evaluate advances every plan and returns runs that must start now. Runs
// are removed from the pending state before they are returned.
func (s *Scheduler) Evaluate(now time.Time, env Env) []Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	runs := []Run{}
	var owners []Owner
	ownersOnce := func() []Owner {
		if owners == nil {
			owners = env.Owners()
		}
		return owners
	}
	day := now.In(s.loc).Format(time.DateOnly)
	for _, p := range s.data.Plans {
		st := s.planState(p.ID)
		if st.Day != day {
			st.Day, st.RunsToday = day, 0
			s.dirty = true
		}
		active := s.data.Settings.Enabled && p.Enabled
		if st.Pending == nil && !active {
			if st.Next != nil || st.Since != nil || st.Note != "" {
				st.Next, st.Since, st.Note = nil, nil, ""
				s.dirty = true
			}
			continue
		}
		if st.Pending == nil {
			if p.Trigger.Kind == TriggerHealth {
				s.evaluateHealth(p, st, now, env, ownersOnce)
			} else {
				s.evaluateTime(p, st, now, env, ownersOnce)
			}
		}
		if st.Pending != nil {
			if run, ok := s.advance(p, st, now, env, active, ownersOnce); ok {
				runs = append(runs, run)
			}
		}
	}
	if s.dirty {
		_ = s.saveLocked()
	}
	return runs
}

func (s *Scheduler) evaluateTime(p Plan, st *PlanState, now time.Time, env Env, owners func() []Owner) {
	if st.Next == nil {
		next := nextTime(p, now, st.Last, s.loc)
		st.Next = &next
		s.dirty = true
		return
	}
	if now.Before(*st.Next) {
		return
	}
	due := *st.Next
	next := nextTime(p, now, &now, s.loc)
	st.Next = &next
	s.dirty = true
	if now.Sub(due) > grace {
		s.skip(p, now, "schedule", "Missed while the panel was not running.")
		return
	}
	if p.Trigger.Kind == TriggerUptime && env.Uptime() < time.Duration(p.Trigger.UptimeDays)*24*time.Hour {
		return
	}
	if reason := s.blocked(p, st, now, env); reason != "" {
		s.skip(p, now, "schedule", reason)
		return
	}
	scoped := targets(p, owners(), nil)
	if p.Action != ActionReboot && len(scoped) == 0 {
		s.skip(p, now, "schedule", "No connection or resource in scope supports this action.")
		return
	}
	ids := []string{}
	for _, o := range scoped {
		ids = append(ids, o.ID)
	}
	st.Pending = &Pending{Reason: "schedule", Owners: ids, Since: now, RunAt: now.Add(time.Duration(p.Guards.Notice) * time.Minute)}
}

func (s *Scheduler) evaluateHealth(p Plan, st *PlanState, now time.Time, env Env, owners func() []Owner) {
	note := ""
	defer func() {
		if st.Note != note {
			st.Note = note
		}
	}()
	if !env.HealthEnabled() {
		note = "Health monitoring is off."
		return
	}
	watched := []Owner{}
	for _, o := range owners() {
		if len(p.Scope) > 0 && !slices.Contains(p.Scope, o.ID) {
			continue
		}
		if p.Action == ActionReboot || Applies(p.Action, o.Engine) {
			watched = append(watched, o)
		}
	}
	if st.Since == nil {
		st.Since = map[string]time.Time{}
	}
	ready := []string{}
	t := p.Trigger
	for _, o := range watched {
		known, down, latency := env.Health(o.ID)
		holds := known && (t.Condition == ConditionDown && down || t.Condition == ConditionLatency && !math.IsNaN(latency) && latency > float64(t.LatencyMs))
		since, tracked := st.Since[o.ID]
		switch {
		case !holds && tracked:
			delete(st.Since, o.ID)
			s.dirty = true
		case holds && !tracked:
			st.Since[o.ID] = now
			s.dirty = true
		case holds && now.Sub(since) >= time.Duration(t.Minutes)*time.Minute:
			ready = append(ready, o.ID)
		}
	}
	for id := range st.Since {
		if !slices.ContainsFunc(watched, func(o Owner) bool { return o.ID == id }) {
			delete(st.Since, id)
		}
	}
	if len(ready) == 0 {
		return
	}
	if !inWindow(p.Guards.Window, now, s.loc) {
		note = "Waiting for the allowed time window."
		return
	}
	if reason := s.blocked(p, st, now, env); reason != "" {
		note = reason
		return
	}
	for _, id := range ready {
		delete(st.Since, id)
	}
	detail := fmt.Sprintf("%s for %d min", t.Condition, t.Minutes)
	st.Pending = &Pending{Reason: "health", Detail: detail, Owners: ready, Since: now, RunAt: now.Add(time.Duration(p.Guards.Notice) * time.Minute)}
	s.dirty = true
}

// advance moves a pending run through its notice and quiet-traffic stages.
func (s *Scheduler) advance(p Plan, st *PlanState, now time.Time, env Env, active bool, owners func() []Owner) (Run, bool) {
	pending := st.Pending
	if !pending.Manual && !active {
		s.record(Entry{Plan: p.ID, PlanName: p.Name, Action: p.Action, Reason: pending.Reason, Started: now, Ended: now, Result: ResultCancelled, Message: "Plan or maintenance was turned off."})
		st.Pending = nil
		return Run{}, false
	}
	if now.Before(pending.RunAt) {
		return Run{}, false
	}
	if !pending.Manual && p.Guards.QuietMbps > 0 {
		mbps, ok := env.Throughput()
		if !ok || mbps >= p.Guards.QuietMbps {
			if pending.Deadline.IsZero() {
				pending.Deadline = pending.RunAt.Add(time.Duration(p.Guards.QuietWait) * time.Minute)
				s.dirty = true
			}
			if now.Before(pending.Deadline) {
				return Run{}, false
			}
			if p.Guards.QuietTimeout != "run" {
				st.Pending = nil
				s.skip(p, now, pending.Reason, "Traffic stayed above the quiet limit.")
				return Run{}, false
			}
		}
	}
	run := Run{Plan: p, Reason: pending.Reason, Detail: pending.Detail}
	if p.Action != ActionReboot {
		run.Owners = targets(p, owners(), pending.Owners)
		if len(run.Owners) == 0 {
			st.Pending = nil
			s.skip(p, now, pending.Reason, "No connection or resource in scope supports this action.")
			return Run{}, false
		}
	}
	st.Pending = nil
	last := now
	st.Last = &last
	st.RunsToday++
	s.dirty = true
	return run, true
}

type PlanView struct {
	Plan
	State PlanState `json:"state"`
}

type View struct {
	Settings Settings   `json:"settings"`
	Revision uint64     `json:"revision"`
	Time     time.Time  `json:"time"`
	Plans    []PlanView `json:"plans"`
	History  []Entry    `json:"history"`
}

func (s *Scheduler) View(now time.Time) View {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := View{Settings: s.data.Settings, Revision: s.data.Revision, Time: now, Plans: []PlanView{}, History: []Entry{}}
	for _, p := range s.data.Plans {
		pv := PlanView{Plan: p}
		if st := s.data.States[p.ID]; st != nil {
			pv.State = *st
			pv.State.Since = nil
		}
		v.Plans = append(v.Plans, pv)
	}
	for i := len(s.data.History) - 1; i >= 0 && len(v.History) < 300; i-- {
		v.History = append(v.History, s.data.History[i])
	}
	return v
}

// History returns entries that started in [from, to), oldest first.
func (s *Scheduler) History(from, to time.Time) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Entry{}
	for _, e := range s.data.History {
		if !e.Started.Before(from) && e.Started.Before(to) {
			out = append(out, e)
		}
	}
	return out
}
