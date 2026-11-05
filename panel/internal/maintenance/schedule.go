package maintenance

import (
	"slices"
	"time"
)

// at returns the local time on day's date at minute m after midnight.
func at(day time.Time, m int, loc *time.Location) time.Time {
	d := day.In(loc)
	return time.Date(d.Year(), d.Month(), d.Day(), m/60, m%60, 0, 0, loc)
}

// inWindow reports whether t falls in the plan's local window (always true
// when no window is set). Windows that wrap past midnight are supported.
func inWindow(value string, t time.Time, loc *time.Location) bool {
	if value == "" {
		return true
	}
	start, end, ok := window(value)
	if !ok {
		return false
	}
	local := t.In(loc)
	m := local.Hour()*60 + local.Minute()
	if start < end {
		return m >= start && m < end
	}
	return m >= start || m < end
}

// windowStart returns the first window opening at or after t.
func windowStart(value string, t time.Time, loc *time.Location) time.Time {
	if inWindow(value, t, loc) {
		return t
	}
	start, _, _ := window(value)
	candidate := at(t, start, loc)
	if !candidate.After(t) {
		candidate = at(t.In(loc).AddDate(0, 0, 1), start, loc)
	}
	return candidate
}

// nextTime returns the first moment strictly after `after` that the
// time-based trigger fires. last is the previous run (interval triggers).
func nextTime(p Plan, after time.Time, last *time.Time, loc *time.Location) time.Time {
	t := p.Trigger
	switch t.Kind {
	case TriggerInterval:
		step := time.Duration(t.Hours) * time.Hour
		next := after.Add(step)
		if last != nil && last.Add(step).After(after) {
			next = last.Add(step)
		}
		if p.Guards.Window != "" {
			next = windowStart(p.Guards.Window, next, loc)
		}
		return next
	case TriggerDaily, TriggerUptime, TriggerWeekly:
		minutes := []int{}
		for _, value := range t.Times {
			if m, ok := minutesOf(value); ok {
				minutes = append(minutes, m)
			}
		}
		slices.Sort(minutes)
		local := after.In(loc)
		for d := 0; d <= 8; d++ {
			day := local.AddDate(0, 0, d)
			if t.Kind == TriggerWeekly && !slices.Contains(t.Days, int(day.Weekday())) {
				continue
			}
			for _, m := range minutes {
				if c := at(day, m, loc); c.After(after) {
					return c
				}
			}
		}
	}
	// Unreachable for valid plans; keep evaluation bounded.
	return after.Add(24 * time.Hour)
}
