package control

import "regexp"

var interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func modelInterface(name string) bool { return interfaceNamePattern.MatchString(name) }

// quotaReached uses cycle totals, never raw kernel counters. Saturating addition
// prevents wrapping a total quota after a long-lived ledger accumulates bytes.
func quotaReached(c Traffic, p TrafficPolicy) bool {
	if p.Limit == 0 {
		return false
	}
	rx, tx := c.Received-c.BaselineReceived, c.Sent-c.BaselineSent
	used := addTraffic(rx, tx)
	if p.Direction == "received" {
		used = rx
	}
	if p.Direction == "sent" {
		used = tx
	}
	return used >= p.Limit
}

func quotaBlocks(v MetricsView) map[string]bool {
	blocked := map[string]bool{}
	for id, p := range v.Policies {
		if p.StopOnLimit && quotaReached(v.Counters[id], p) {
			blocked[id] = true
		}
	}
	return blocked
}

func quotaSelectionsValid(v MetricsView, s MetricsSettings, inv Inventory) bool {
	for id, p := range v.Policies {
		if p.StopOnLimit && trafficAvailable(inv, id) && (!s.Enabled || !wanted(s.IDs, id)) {
			return false
		}
	}
	return true
}
