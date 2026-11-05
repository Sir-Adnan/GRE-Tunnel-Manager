package maintenance

import (
	"math"
	"path/filepath"
	"testing"
	"time"
)

type fakeEnv struct {
	owners  []Owner
	uptime  time.Duration
	mbps    float64
	health  bool
	down    map[string]bool
	latency map[string]float64
}

func (f *fakeEnv) Owners() []Owner             { return f.owners }
func (f *fakeEnv) Uptime() time.Duration       { return f.uptime }
func (f *fakeEnv) Throughput() (float64, bool) { return f.mbps, true }
func (f *fakeEnv) HealthEnabled() bool         { return f.health }
func (f *fakeEnv) Health(id string) (bool, bool, float64) {
	l, ok := f.latency[id]
	if !ok {
		l = math.NaN()
	}
	return true, f.down[id], l
}

var tehran, _ = time.LoadLocation("Asia/Tehran")

func env() *fakeEnv {
	return &fakeEnv{owners: []Owner{{ID: "F000001", Name: "Reality", Engine: "nftables"}, {ID: "F000002", Name: "Relay", Engine: "realm"}, {ID: "gre-tun-3", Name: "GRE 3", Engine: "gre"}}, uptime: 72 * time.Hour, health: true, down: map[string]bool{}, latency: map[string]float64{}}
}

func scheduler(t *testing.T) *Scheduler {
	t.Helper()
	s := New()
	if e := s.Configure(Settings{Enabled: true, Timezone: "Asia/Tehran"}, 0); e != nil {
		t.Fatal(e)
	}
	return s
}

func save(t *testing.T, s *Scheduler, now time.Time, p Plan) Plan {
	t.Helper()
	stored, e := s.Save(now, p, s.View(now).Revision)
	if e != nil {
		t.Fatal(e)
	}
	return stored
}

func daily(times ...string) Plan {
	return Plan{Name: "Nightly", Enabled: true, Action: ActionRestart, Trigger: Trigger{Kind: TriggerDaily, Times: times}, Guards: Guards{Cooldown: 60, MaxPerDay: 2}}
}

func TestDailyPlanRunsAtLocalTimeOnce(t *testing.T) {
	s, e := scheduler(t), env()
	start := time.Date(2026, 11, 4, 2, 0, 0, 0, tehran)
	p := save(t, s, start, daily("04:30"))
	if runs := s.Evaluate(start, e); len(runs) != 0 {
		t.Fatal("first evaluation only schedules")
	}
	next := *s.View(start).Plans[0].State.Next
	if want := time.Date(2026, 11, 4, 4, 30, 0, 0, tehran); !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
	if runs := s.Evaluate(next.Add(-time.Second), e); len(runs) != 0 {
		t.Fatal("ran early")
	}
	runs := s.Evaluate(next.Add(5*time.Second), e)
	if len(runs) != 1 || runs[0].Plan.ID != p.ID || len(runs[0].Owners) != 3 || runs[0].Reason != "schedule" {
		t.Fatalf("due run = %+v", runs)
	}
	if runs := s.Evaluate(next.Add(10*time.Second), e); len(runs) != 0 {
		t.Fatal("ran twice")
	}
	if got := *s.View(start).Plans[0].State.Next; !got.Equal(next.AddDate(0, 0, 1)) {
		t.Fatalf("following run = %v", got)
	}
}

func TestMissedRunIsRecordedNotRunLate(t *testing.T) {
	s, e := scheduler(t), env()
	start := time.Date(2026, 11, 4, 2, 0, 0, 0, tehran)
	save(t, s, start, daily("04:30"))
	s.Evaluate(start, e)
	late := time.Date(2026, 11, 4, 6, 0, 0, 0, tehran)
	if runs := s.Evaluate(late, e); len(runs) != 0 {
		t.Fatal("a run hours late must not start")
	}
	if h := s.View(late).History; len(h) != 1 || h[0].Result != ResultSkipped {
		t.Fatalf("history = %+v", h)
	}
}

func TestNoticeCountdownCanBeCancelled(t *testing.T) {
	s, e := scheduler(t), env()
	start := time.Date(2026, 11, 4, 4, 0, 0, 0, tehran)
	p := daily("04:30")
	p.Action, p.Guards.Notice, p.Guards.MinUptime = ActionReboot, 5, 30
	p = save(t, s, start, p)
	s.Evaluate(start, e)
	due := time.Date(2026, 11, 4, 4, 30, 0, 0, tehran)
	if runs := s.Evaluate(due, e); len(runs) != 0 {
		t.Fatal("notice must delay the reboot")
	}
	if pending := s.View(due).Plans[0].State.Pending; pending == nil || !pending.RunAt.Equal(due.Add(5*time.Minute)) {
		t.Fatalf("pending = %+v", pending)
	}
	if e := s.Cancel(due.Add(time.Minute), p.ID); e != nil {
		t.Fatal(e)
	}
	if runs := s.Evaluate(due.Add(6*time.Minute), e); len(runs) != 0 {
		t.Fatal("cancelled run started")
	}
	if h := s.View(due).History; h[0].Result != ResultCancelled {
		t.Fatalf("history = %+v", h)
	}
}

func TestRebootLoopGuardAndCooldown(t *testing.T) {
	s, e := scheduler(t), env()
	e.uptime = 10 * time.Minute
	start := time.Date(2026, 11, 4, 4, 0, 0, 0, tehran)
	p := daily("04:30")
	p.Action, p.Guards.MinUptime = ActionReboot, 30
	save(t, s, start, p)
	s.Evaluate(start, e)
	due := time.Date(2026, 11, 4, 4, 30, 0, 0, tehran)
	if runs := s.Evaluate(due, e); len(runs) != 0 {
		t.Fatal("reboot right after boot must be refused")
	}
	if h := s.View(due).History; h[0].Message != "Server started recently; reboot loop guard." {
		t.Fatalf("history = %+v", h)
	}
}

func TestQuietTrafficWaitsThenSkips(t *testing.T) {
	s, e := scheduler(t), env()
	e.mbps = 80
	start := time.Date(2026, 11, 4, 4, 0, 0, 0, tehran)
	p := daily("04:30")
	p.Guards.QuietMbps, p.Guards.QuietWait = 20, 30
	save(t, s, start, p)
	s.Evaluate(start, e)
	due := time.Date(2026, 11, 4, 4, 30, 0, 0, tehran)
	if runs := s.Evaluate(due, e); len(runs) != 0 {
		t.Fatal("busy traffic must wait")
	}
	e.mbps = 5
	if runs := s.Evaluate(due.Add(10*time.Minute), e); len(runs) != 1 {
		t.Fatal("quiet traffic should start the run")
	}
	// Next day: traffic never quiets; default timeout skips.
	e.mbps = 80
	tomorrow := due.AddDate(0, 0, 1)
	s.Evaluate(tomorrow, e)
	if runs := s.Evaluate(tomorrow.Add(31*time.Minute), e); len(runs) != 0 {
		t.Fatal("timeout must skip")
	}
	if h := s.View(tomorrow).History; h[0].Message != "Traffic stayed above the quiet limit." {
		t.Fatalf("history = %+v", h)
	}
}

func TestHealthTriggerWaitsForDurationAndTargetsOnlyAffectedOwners(t *testing.T) {
	s, e := scheduler(t), env()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, tehran)
	p := Plan{Name: "Heal", Enabled: true, Action: ActionRestart, Trigger: Trigger{Kind: TriggerHealth, Condition: ConditionDown, Minutes: 3}, Guards: Guards{Cooldown: 30, MaxPerDay: 4}}
	save(t, s, now, p)
	e.down["gre-tun-3"] = true
	if runs := s.Evaluate(now, e); len(runs) != 0 {
		t.Fatal("condition must hold for the duration")
	}
	if runs := s.Evaluate(now.Add(2*time.Minute), e); len(runs) != 0 {
		t.Fatal("ran before three minutes")
	}
	runs := s.Evaluate(now.Add(3*time.Minute), e)
	if len(runs) != 1 || len(runs[0].Owners) != 1 || runs[0].Owners[0].ID != "gre-tun-3" {
		t.Fatalf("runs = %+v", runs)
	}
	// Still down: the condition re-arms, then the cooldown holds the next attempt.
	s.Evaluate(now.Add(10*time.Minute), e)
	if runs := s.Evaluate(now.Add(14*time.Minute), e); len(runs) != 0 {
		t.Fatal("cooldown ignored")
	}
	if note := s.View(now).Plans[0].State.Note; note == "" {
		t.Fatal("waiting reason should be visible")
	}
	e.health = false
	s.Evaluate(now.Add(11*time.Minute), e)
	if note := s.View(now).Plans[0].State.Note; note != "Health monitoring is off." {
		t.Fatalf("note = %q", note)
	}
}

func TestLatencyConditionAndRefreshApplicability(t *testing.T) {
	s, e := scheduler(t), env()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, tehran)
	p := Plan{Name: "Slow", Enabled: true, Action: ActionRefresh, Trigger: Trigger{Kind: TriggerHealth, Condition: ConditionLatency, Minutes: 1, LatencyMs: 200}, Guards: Guards{MaxPerDay: 4}}
	save(t, s, now, p)
	e.latency["F000001"], e.latency["F000002"] = 500, 500
	s.Evaluate(now, e)
	runs := s.Evaluate(now.Add(time.Minute), e)
	// Realm has no non-disruptive refresh, so only the kernel forward runs.
	if len(runs) != 1 || len(runs[0].Owners) != 1 || runs[0].Owners[0].ID != "F000001" {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestIntervalRespectsWindow(t *testing.T) {
	s, e := scheduler(t), env()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, tehran)
	p := Plan{Name: "Every 6h", Enabled: true, Action: ActionRefresh, Trigger: Trigger{Kind: TriggerInterval, Hours: 6}, Guards: Guards{Window: "02:00-05:00", MaxPerDay: 4}}
	save(t, s, now, p)
	s.Evaluate(now, e)
	next := *s.View(now).Plans[0].State.Next
	if want := time.Date(2026, 11, 5, 2, 0, 0, 0, tehran); !next.Equal(want) {
		t.Fatalf("next = %v, want %v (18:00 is outside the window)", next, want)
	}
	if !inWindow("23:00-05:00", time.Date(2026, 11, 4, 1, 0, 0, 0, tehran), tehran) || inWindow("23:00-05:00", time.Date(2026, 11, 4, 12, 0, 0, 0, tehran), tehran) {
		t.Fatal("wrapping window")
	}
}

func TestWeeklyAndUptimeTriggers(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, tehran) // Wednesday
	p := Plan{Action: ActionReboot, Trigger: Trigger{Kind: TriggerWeekly, Days: []int{5}, Times: []string{"04:30"}}}
	if got := nextTime(p, now, nil, tehran); !got.Equal(time.Date(2026, 11, 6, 4, 30, 0, 0, tehran)) {
		t.Fatalf("weekly next = %v", got)
	}
	s, e := scheduler(t), env()
	e.uptime = 2 * 24 * time.Hour
	up := Plan{Name: "Uptime", Enabled: true, Action: ActionReboot, Trigger: Trigger{Kind: TriggerUptime, UptimeDays: 7, Times: []string{"04:30"}}, Guards: Guards{MaxPerDay: 1}}
	save(t, s, now, up)
	s.Evaluate(now, e)
	due := time.Date(2026, 11, 5, 4, 30, 0, 0, tehran)
	if runs := s.Evaluate(due, e); len(runs) != 0 {
		t.Fatal("uptime below threshold must not reboot")
	}
	e.uptime = 8 * 24 * time.Hour
	if runs := s.Evaluate(due.AddDate(0, 0, 1), e); len(runs) != 1 {
		t.Fatal("uptime above threshold should reboot")
	}
}

func TestManualRunBypassesGuardsAndDisabledModule(t *testing.T) {
	s, e := New(), env()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, tehran)
	p := daily("04:30")
	p.Scope = []string{"F000002"}
	p = save(t, s, now, p)
	if e := s.Queue(now, p.ID); e != nil {
		t.Fatal(e)
	}
	if e := s.Queue(now, p.ID); e == nil {
		t.Fatal("double queue accepted")
	}
	runs := s.Evaluate(now, e)
	if len(runs) != 1 || runs[0].Reason != "manual" || len(runs[0].Owners) != 1 || runs[0].Owners[0].ID != "F000002" {
		t.Fatalf("manual run = %+v", runs)
	}
}

func TestValidationRejectsUnsafePlans(t *testing.T) {
	cases := []Plan{
		{Name: "", Action: ActionRestart, Trigger: Trigger{Kind: TriggerInterval, Hours: 1}, Guards: Guards{MaxPerDay: 1}},
		{Name: "x", Action: "shell", Trigger: Trigger{Kind: TriggerInterval, Hours: 1}, Guards: Guards{MaxPerDay: 1}},
		{Name: "x", Action: ActionReboot, Scope: []string{"F000001"}, Trigger: Trigger{Kind: TriggerDaily, Times: []string{"04:00"}}, Guards: Guards{MaxPerDay: 1}},
		{Name: "x", Action: ActionRestart, Trigger: Trigger{Kind: TriggerDaily, Times: []string{"24:00"}}, Guards: Guards{MaxPerDay: 1}},
		{Name: "x", Action: ActionRestart, Trigger: Trigger{Kind: TriggerUptime, UptimeDays: 3, Times: []string{"04:00"}}, Guards: Guards{MaxPerDay: 1}},
		{Name: "x", Action: ActionRestart, Trigger: Trigger{Kind: TriggerHealth, Condition: ConditionLatency, Minutes: 5}, Guards: Guards{MaxPerDay: 1}},
		{Name: "x", Action: ActionRestart, Scope: []string{"bad id;"}, Trigger: Trigger{Kind: TriggerInterval, Hours: 1}, Guards: Guards{MaxPerDay: 1}},
		{Name: "x", Action: ActionRestart, Trigger: Trigger{Kind: TriggerInterval, Hours: 1}, Guards: Guards{MaxPerDay: 0}},
		{Name: "x", Action: ActionRestart, Trigger: Trigger{Kind: TriggerInterval, Hours: 1}, Guards: Guards{MaxPerDay: 1, Window: "05:00-05:00"}},
	}
	for i, p := range cases {
		p.normalize()
		if p.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, p)
		}
	}
}

func TestPersistenceRevisionAndRebootResolution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maintenance.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Configure(Settings{Enabled: true, Timezone: "Mars/Olympus"}, 0); err == nil {
		t.Fatal("unknown zone accepted")
	}
	if err = s.Configure(Settings{Enabled: true, Timezone: "UTC"}, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 4, 4, 0, 0, 0, time.UTC)
	p, err := s.Save(now, Plan{Name: "Weekly reboot", Enabled: true, Action: ActionReboot, Trigger: Trigger{Kind: TriggerDaily, Times: []string{"04:30"}}, Guards: Guards{MaxPerDay: 1}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Save(now, p, 0); err == nil {
		t.Fatal("stale revision accepted")
	}
	run := Run{Plan: p, Reason: "schedule"}
	if err = s.Finish(run, []Entry{{Started: now, Ended: now, Result: ResultRebooting}}); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = again.ResolveReboots(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	v := again.View(now)
	if len(v.Plans) != 1 || v.History[0].Result != ResultOK || v.Plans[0].State.LastResult != ResultOK {
		t.Fatalf("restored view = %+v", v)
	}
	if err = again.Delete(p.ID, v.Revision); err != nil || len(again.View(now).Plans) != 0 {
		t.Fatalf("delete: %v", err)
	}
}
