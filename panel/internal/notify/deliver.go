package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/version"
)

// Delivery limits: at most rateLimit external messages per rateWindow; the
// rest stay in the panel and one summary follows when the window ends.
const (
	rateLimit  = 20
	rateWindow = 10 * time.Minute
	attempts   = 3
)

// retryDelays separates the attempts of one delivery.
var retryDelays = []time.Duration{10 * time.Second, time.Minute}

// Sender posts one rendered event. The HTTP client honors HTTPS_PROXY.
type Sender struct {
	Client *http.Client
}

func (s Sender) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

type payload struct {
	ID       uint64    `json:"id"`
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Owner    string    `json:"owner,omitempty"`
	Name     string    `json:"name,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Host     string    `json:"host,omitempty"`
	// Text is the rendered message; Content repeats it for Discord.
	Text    string `json:"text"`
	Content string `json:"content"`
}

func (s Sender) post(ctx context.Context, address string, body []byte, header http.Header) error {
	request, e := http.NewRequestWithContext(ctx, "POST", address, bytes.NewReader(body))
	if e != nil {
		return e
	}
	request.Header = header
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "gtm-panel/"+version.Number)
	response, e := s.client().Do(request)
	if e != nil {
		// The URL can carry a secret; report only the kind of failure.
		var u interface{ Timeout() bool }
		if errors.As(e, &u) && u.Timeout() {
			return errors.New("timed out")
		}
		return errors.New("connection failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 65536))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return nil
}

func (s Sender) webhook(ctx context.Context, w Webhook, e Event, language, host string) error {
	text := e.Text(language, host)
	body, err := json.Marshal(payload{ID: e.ID, Time: e.Time, Kind: e.Kind, Severity: e.Severity, Owner: e.Owner, Name: e.Name, Detail: e.Detail, Host: host, Text: text, Content: text})
	if err != nil {
		return err
	}
	header := http.Header{}
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		header.Set("X-GTM-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	return s.post(ctx, w.URL, body, header)
}

func (s Sender) telegram(ctx context.Context, t Telegram, e Event, language, host string) error {
	api := t.API
	if api == "" {
		api = DefaultTelegramAPI
	}
	body, err := json.Marshal(map[string]any{"chat_id": t.Chat, "text": e.Text(language, host), "disable_web_page_preview": true})
	if err != nil {
		return err
	}
	return s.post(ctx, strings.TrimRight(api, "/")+"/bot"+t.Token+"/sendMessage", body, http.Header{})
}

// Send delivers to every enabled channel; the error names failed channels.
func (s Sender) Send(ctx context.Context, settings Settings, e Event, host string) error {
	failed := []string{}
	if settings.Webhook.Enabled && settings.Webhook.URL != "" {
		if err := s.webhook(ctx, settings.Webhook, e, settings.Language, host); err != nil {
			failed = append(failed, "webhook: "+err.Error())
		}
	}
	if settings.Telegram.Enabled && settings.Telegram.Token != "" {
		if err := s.telegram(ctx, settings.Telegram, e, settings.Language, host); err != nil {
			failed = append(failed, "Telegram: "+err.Error())
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

// Test sends a test message now and reports the result per channel.
func (c *Center) Test(ctx context.Context, s Sender) error {
	settings := c.settings()
	if !settings.Webhook.Enabled && !settings.Telegram.Enabled {
		return errors.New("turn on a webhook or Telegram first")
	}
	e := c.Emit(Event{Kind: KindTest})
	err := s.Send(ctx, settings, e, c.Host)
	state := DeliverySent
	if err != nil {
		state = DeliveryFailed
	}
	c.setDelivery(e.ID, state)
	return err
}

// Run delivers queued events until ctx ends. Each event gets up to three
// attempts; deliveries over the rate limit are summarized once.
func (c *Center) Run(ctx context.Context, s Sender) {
	windowStart, sent, limited := time.Now(), 0, 0
	for {
		var id uint64
		select {
		case <-ctx.Done():
			return
		case id = <-c.queue:
		case <-time.After(time.Minute):
		}
		now := time.Now()
		if now.Sub(windowStart) >= rateWindow {
			if limited > 0 {
				summary := Event{Time: now.UTC(), Kind: kindLimited, Severity: SeverityWarning, Detail: fmt.Sprintf("%d over the rate limit; see the panel.", limited)}
				_ = s.Send(ctx, c.settings(), summary, c.Host)
			}
			windowStart, sent, limited = now, 0, 0
		}
		if id == 0 {
			continue
		}
		e, ok := c.event(id)
		if !ok {
			continue
		}
		if sent >= rateLimit {
			limited++
			c.setDelivery(id, DeliveryLimited)
			continue
		}
		sent++
		state := DeliveryFailed
		for attempt := 0; attempt < attempts; attempt++ {
			if attempt > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(retryDelays[attempt-1]):
				}
			}
			send, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := s.Send(send, c.settings(), e, c.Host)
			cancel()
			if err == nil {
				state = DeliverySent
				break
			}
		}
		c.setDelivery(id, state)
	}
}
