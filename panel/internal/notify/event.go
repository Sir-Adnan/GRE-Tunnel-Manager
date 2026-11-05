// Package notify keeps a bounded in-panel notification list and delivers
// selected kinds to an optional webhook and Telegram bot. It runs no
// commands; delivery is one bounded background worker that sends nothing
// while every channel is off.
package notify

import (
	"fmt"
	"strings"
	"time"
)

// Event kinds. Every kind is listed in the panel; Settings.Kinds selects the
// ones sent to external channels.
const (
	KindDown              = "down"
	KindUp                = "up"
	KindFailover          = "failover"
	KindMaintenance       = "maintenance"
	KindMaintenanceFailed = "maintenance-failed"
	KindRollback          = "optimize-rollback"
	KindOptimizeKept      = "optimize-kept"
	KindBackup            = "backup"
	KindBackupFailed      = "backup-failed"
	KindTest              = "test"
	KindChangeReverted    = "change-reverted"
	// kindLimited summarizes deliveries skipped by the rate limit.
	kindLimited = "limited"
)

// Kinds lists every kind in the order the settings show them.
var Kinds = []string{KindDown, KindUp, KindFailover, KindRollback, KindChangeReverted, KindOptimizeKept, KindMaintenanceFailed, KindMaintenance, KindBackupFailed, KindBackup}

// DefaultKinds are delivered externally on a fresh installation: problems
// and their recovery, not routine successes.
var DefaultKinds = []string{KindDown, KindUp, KindRollback, KindChangeReverted, KindMaintenanceFailed, KindBackupFailed}

const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Delivery states of one event.
const (
	DeliveryPending = "pending"
	DeliverySent    = "sent"
	DeliveryFailed  = "failed"
	DeliveryLimited = "limited"
)

// Event is one notification. Detail is short, technical and untranslated
// (an endpoint, a reason code, a duration); the interface localizes Kind.
type Event struct {
	ID       uint64    `json:"id"`
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Owner    string    `json:"owner,omitempty"`
	Name     string    `json:"name,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	// Args carry the values of a localized detail (seconds, names, counts);
	// Detail stays the untranslated fallback.
	Args     map[string]string `json:"args,omitempty"`
	Read     bool              `json:"read"`
	Delivery string            `json:"delivery,omitempty"`
}

func severityOf(kind string) string {
	switch kind {
	case KindDown:
		return SeverityCritical
	case KindRollback, KindChangeReverted, KindMaintenanceFailed, KindBackupFailed, KindFailover:
		return SeverityWarning
	}
	return SeverityInfo
}

func knownKind(kind string) bool {
	if kind == KindTest {
		return true
	}
	for _, k := range Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

var titles = map[string][2]string{
	KindDown:              {"%s is down", "%s قطع است"},
	KindUp:                {"%s is back up", "%s دوباره وصل شد"},
	KindFailover:          {"Failover changed destinations of %s", "جابه‌جایی مقصدهای %s تغییر کرد"},
	KindMaintenance:       {"Maintenance finished: %s", "نگهداری انجام شد: %s"},
	KindMaintenanceFailed: {"Maintenance failed: %s", "نگهداری ناموفق بود: %s"},
	KindRollback:          {"Optimization was undone automatically", "بهینه‌سازی خودکار برگردانده شد"},
	KindChangeReverted:    {"Unconfirmed change was reverted", "تغییر تأییدنشده برگردانده شد"},
	KindOptimizeKept:      {"Optimization kept: tunnels stayed healthy", "بهینه‌سازی ماند: تونل‌ها سالم ماندند"},
	KindBackup:            {"Scheduled backup saved", "پشتیبان زمان‌بندی‌شده ذخیره شد"},
	KindBackupFailed:      {"Scheduled backup failed", "پشتیبان زمان‌بندی‌شده ناموفق بود"},
	KindTest:              {"Test notification from Traffic Manager", "اعلان آزمایشی از Traffic Manager"},
	kindLimited:           {"Some notifications were not sent", "برخی اعلان‌ها ارسال نشدند"},
}

var icons = map[string]string{SeverityCritical: "🔴", SeverityWarning: "🟠", SeverityInfo: "🟢"}

// Text renders the external message in English or Persian.
func (e Event) Text(language, host string) string {
	index := 0
	if language == "fa" {
		index = 1
	}
	title := titles[e.Kind][index]
	if title == "" {
		title = e.Kind
	}
	if strings.Contains(title, "%s") {
		name := e.Name
		if name == "" {
			name = e.Owner
		}
		title = fmt.Sprintf(title, name)
	}
	lines := []string{icons[e.Severity] + " " + title}
	if detail := e.localDetail(index); detail != "" {
		lines = append(lines, detail)
	}
	footer := e.Time.UTC().Format("2006-01-02 15:04 UTC")
	if host != "" {
		footer = host + " · " + footer
	}
	return strings.Join(append(lines, footer), "\n")
}

// localDetail renders Args in English (0) or Persian (1); Detail otherwise.
func (e Event) localDetail(lang int) string {
	a := e.Args
	pick := func(en, fa string) string { return [2]string{en, fa}[lang] }
	switch {
	case e.Kind == KindUp && a["seconds"] != "":
		return pick("Down for ", "مدت قطعی: ") + duration(a["seconds"], lang)
	case e.Kind == KindFailover && a != nil && a["excluded"] == "":
		return pick("Every destination receives new flows again.", "همهٔ مقصدها دوباره اتصال جدید می‌گیرند.")
	case e.Kind == KindFailover && a["excluded"] != "":
		return pick("No new flows to destination ", "مقصد بدون اتصال جدید: ") + a["excluded"]
	case e.Kind == KindOptimizeKept && a["minutes"] != "":
		return pick("Watched for "+a["minutes"]+" minutes.", a["minutes"]+" دقیقه پایش شد.")
	case e.Kind == KindRollback && a["names"] != "" && a["error"] == "":
		return pick("Down after the apply: ", "قطع‌شده بعد از اعمال: ") + a["names"]
	case e.Kind == KindBackup && a["name"] != "":
		return a["name"] + " · " + a["connections"] + pick(" connections", " اتصال")
	case (e.Kind == KindMaintenance || e.Kind == KindMaintenanceFailed) && a["count"] != "" && e.Detail == "":
		return a["count"] + pick(" targets", " مورد")
	}
	return e.Detail
}

// duration renders seconds as "2h 5m" or "2 ساعت 5 دقیقه".
func duration(value string, lang int) string {
	var s int64
	for _, c := range value {
		if c < '0' || c > '9' {
			return value
		}
		s = s*10 + int64(c-'0')
	}
	units := [2][3]string{{"d", "h", "m"}, {" روز", " ساعت", " دقیقه"}}[lang]
	parts := []string{}
	for i, size := range []int64{86400, 3600, 60} {
		if n := s / size; n > 0 && len(parts) < 2 {
			parts = append(parts, fmt.Sprintf("%d%s", n, units[i]))
			s %= size
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d%s", s, [2]string{"s", " ثانیه"}[lang])
	}
	return strings.Join(parts, " ")
}
