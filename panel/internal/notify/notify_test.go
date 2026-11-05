package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSettingsValidateMergeAndHideSecrets(t *testing.T) {
	c := New()
	bad := []Settings{
		{Language: "de"},
		{Language: "en", Kinds: []string{"nope"}},
		{Language: "en", Webhook: Webhook{Enabled: true}},
		{Language: "en", Webhook: Webhook{URL: "ftp://example.com/x"}},
		{Language: "en", Webhook: Webhook{URL: "https://user:pw@example.com/x"}},
		{Language: "en", Telegram: Telegram{Enabled: true, Token: "123456:" + strings.Repeat("a", 35)}},
		{Language: "en", Telegram: Telegram{Token: "nope", Chat: "1"}},
		{Language: "en", Telegram: Telegram{Chat: "not a chat"}},
		{Language: "en", Telegram: Telegram{API: "http://relay.example"}},
	}
	for i, s := range bad {
		if e := c.Configure(s, 0); e == nil {
			t.Fatalf("case %d accepted: %+v", i, s)
		}
	}
	token := "123456:" + strings.Repeat("b", 35)
	good := Settings{Language: "fa", Kinds: []string{KindDown}, Webhook: Webhook{Enabled: true, URL: "https://hooks.example.com/secret-path", Secret: "s3cret-value"}, Telegram: Telegram{Enabled: true, Token: token, Chat: "-100123"}}
	if e := c.Configure(good, 0); e != nil {
		t.Fatal(e)
	}
	if e := c.Configure(good, 0); e == nil {
		t.Fatal("stale revision accepted")
	}
	v := c.View()
	data, _ := json.Marshal(v)
	if strings.Contains(string(data), "secret-path") || strings.Contains(string(data), token) || strings.Contains(string(data), "s3cret") {
		t.Fatalf("view leaks a secret: %s", data)
	}
	if !v.Settings.Webhook.URLSet || v.Settings.Webhook.Host != "https://hooks.example.com" || !v.Settings.Telegram.TokenSet {
		t.Fatalf("view = %+v", v.Settings)
	}
	// Empty secrets keep the stored ones; Forget clears them.
	keep := Settings{Language: "en", Kinds: []string{}, Webhook: Webhook{Enabled: true}, Telegram: Telegram{Chat: "@ops_alerts"}}
	if e := c.Configure(keep, v.Revision); e != nil {
		t.Fatal(e)
	}
	if s := c.settings(); s.Webhook.URL == "" || s.Telegram.Token != token {
		t.Fatalf("secrets lost: %+v", s)
	}
	if e := c.Configure(Settings{Language: "en", Webhook: Webhook{Forget: true}, Telegram: Telegram{Forget: true}}, v.Revision+1); e != nil {
		t.Fatal(e)
	}
	if s := c.settings(); s.Webhook.URL != "" || s.Webhook.Secret != "" || s.Telegram.Token != "" {
		t.Fatalf("forget kept secrets: %+v", s)
	}
}

func TestEventsAreBoundedReadAndPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notifications.json")
	c, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < maxEvents+10; i++ {
		c.Emit(Event{Kind: KindDown, Owner: "F000001", Name: strings.Repeat("n", 200)})
	}
	v := c.View()
	if len(v.Events) != viewEvents || v.Unread != maxEvents || v.Events[0].ID != uint64(maxEvents+10) || len(v.Events[0].Name) != 80 {
		t.Fatalf("view: %d events, %d unread, first %d", len(v.Events), v.Unread, v.Events[0].ID)
	}
	if v.Events[0].Severity != SeverityCritical || v.Events[0].Delivery != "" {
		t.Fatalf("event = %+v", v.Events[0])
	}
	if e = c.MarkRead([]uint64{v.Events[0].ID}, false); e != nil {
		t.Fatal(e)
	}
	again, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if got := again.View(); got.Unread != maxEvents-1 || got.Events[0].ID != v.Events[0].ID {
		t.Fatalf("reloaded: %d unread", got.Unread)
	}
	if e = again.MarkRead(nil, true); e != nil || again.View().Unread != 0 {
		t.Fatal("mark all failed")
	}
	if e = again.Clear(); e != nil || len(again.View().Events) != 0 {
		t.Fatal("clear failed")
	}
}

func TestDeliveryToWebhookAndTelegram(t *testing.T) {
	type hit struct {
		path, signature string
		body            map[string]any
		raw             []byte
	}
	hits := make(chan hit, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		hits <- hit{r.URL.Path, r.Header.Get("X-GTM-Signature"), body, raw}
	}))
	defer server.Close()
	c := New()
	c.Host = "edge-01"
	token := "123456:" + strings.Repeat("c", 35)
	// The test server is http; the Telegram API must be https, so the
	// stored settings are written directly for this test.
	c.data.Settings = Settings{Language: "en", Kinds: []string{KindDown}, Webhook: Webhook{Enabled: true, URL: server.URL + "/hook", Secret: "signing-key"}, Telegram: Telegram{Enabled: true, Token: token, Chat: "42", API: server.URL}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, Sender{Client: server.Client()})
	c.Emit(Event{Kind: KindUp, Name: "skipped"})
	e := c.Emit(Event{Kind: KindDown, Owner: "F000002", Name: "WireGuard", Detail: "198.51.100.30 · timeout"})
	got := map[string]hit{}
	for len(got) < 2 {
		select {
		case h := <-hits:
			got[h.path] = h
		case <-time.After(5 * time.Second):
			t.Fatalf("deliveries: %v", got)
		}
	}
	hook := got["/hook"]
	mac := hmac.New(sha256.New, []byte("signing-key"))
	mac.Write(hook.raw)
	if hook.signature != "sha256="+hex.EncodeToString(mac.Sum(nil)) || hook.body["kind"] != KindDown || !strings.Contains(hook.body["content"].(string), "WireGuard is down") {
		t.Fatalf("webhook = %+v", hook)
	}
	tg := got["/bot"+token+"/sendMessage"]
	if tg.body["chat_id"] != "42" || !strings.Contains(tg.body["text"].(string), "edge-01") {
		t.Fatalf("telegram = %+v", tg)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if ev, _ := c.event(e.ID); ev.Delivery == DeliverySent {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("delivery not recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ev, _ := c.event(e.ID - 1); ev.Delivery != "" {
		t.Fatalf("unselected kind was queued: %+v", ev)
	}
}

func TestPersianTextAndFailedSend(t *testing.T) {
	e := Event{Kind: KindRollback, Severity: SeverityWarning, Detail: "down after apply: A", Time: time.Unix(0, 0)}
	if text := e.Text("fa", "edge"); !strings.Contains(text, "بهینه‌سازی خودکار برگردانده شد") || !strings.Contains(text, "edge · 1970-01-01 00:00 UTC") {
		t.Fatal(text)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer server.Close()
	err := Sender{Client: server.Client()}.Send(context.Background(), Settings{Webhook: Webhook{Enabled: true, URL: server.URL + "/secret"}}, e, "")
	if err == nil || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("err = %v", err)
	}
}
