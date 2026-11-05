// Package health turns periodic, bounded reachability probes into status,
// uptime, outage history and weekly reports. It owns no goroutines and runs no
// commands: the broker decides when to probe and passes the results in.
package health

import "errors"

// Settings are operator choices. The zero value is not valid; use Defaults.
type Settings struct {
	Enabled bool `json:"enabled"`
	// Interval is the number of seconds between probe rounds.
	Interval int `json:"interval"`
	// FailThreshold consecutive failures mark a target down.
	FailThreshold int `json:"fail_threshold"`
	// RecoverThreshold consecutive successes bring a down target back up.
	RecoverThreshold int `json:"recover_threshold"`
	// LatencyWarn marks an answering target degraded above this RTT; 0 disables it.
	LatencyWarn int `json:"latency_warn_ms"`
	// RetentionDays bounds hourly rollups and closed outages.
	RetentionDays int `json:"retention_days"`
}

// Defaults are the documented first-run values; monitoring starts disabled.
func Defaults() Settings {
	return Settings{Interval: 30, FailThreshold: 3, RecoverThreshold: 2, LatencyWarn: 300, RetentionDays: 30}
}

func (s Settings) Validate() error {
	switch {
	case s.Interval < 10 || s.Interval > 300:
		return errors.New("probe interval must be 10–300 seconds")
	case s.FailThreshold < 1 || s.FailThreshold > 10 || s.RecoverThreshold < 1 || s.RecoverThreshold > 10:
		return errors.New("failure and recovery thresholds must be 1–10 checks")
	case s.LatencyWarn != 0 && (s.LatencyWarn < 20 || s.LatencyWarn > 5000):
		return errors.New("latency warning must be 0 (off) or 20–5000 ms")
	case s.RetentionDays < 1 || s.RetentionDays > 90:
		return errors.New("history retention must be 1–90 days")
	}
	return nil
}
