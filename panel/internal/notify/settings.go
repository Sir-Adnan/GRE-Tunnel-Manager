package notify

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Settings are operator choices. Secrets (the webhook URL and signing
// secret, the bot token) are stored root-only and never returned.
type Settings struct {
	Kinds    []string `json:"kinds"`
	Language string   `json:"language"`
	Webhook  Webhook  `json:"webhook"`
	Telegram Telegram `json:"telegram"`
}

// Webhook posts one JSON object per event; Secret signs the body with
// HMAC-SHA256 in X-GTM-Signature.
type Webhook struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url,omitempty"`
	Secret  string `json:"secret,omitempty"`
	// Forget clears the stored URL and secret (input only).
	Forget bool `json:"forget,omitempty"`
}

// Telegram sends messages through a bot. API overrides the Bot API base
// for a self-hosted Bot API server or a relay.
type Telegram struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token,omitempty"`
	Chat    string `json:"chat,omitempty"`
	API     string `json:"api,omitempty"`
	Forget  bool   `json:"forget,omitempty"`
}

// SettingsView is what the panel may show.
type SettingsView struct {
	Kinds    []string `json:"kinds"`
	Language string   `json:"language"`
	Webhook  struct {
		Enabled   bool   `json:"enabled"`
		URLSet    bool   `json:"url_set"`
		Host      string `json:"host,omitempty"`
		SecretSet bool   `json:"secret_set"`
	} `json:"webhook"`
	Telegram struct {
		Enabled  bool   `json:"enabled"`
		TokenSet bool   `json:"token_set"`
		Chat     string `json:"chat,omitempty"`
		API      string `json:"api,omitempty"`
	} `json:"telegram"`
}

const DefaultTelegramAPI = "https://api.telegram.org"

var (
	tokenPattern  = regexp.MustCompile(`^[0-9]{5,12}:[A-Za-z0-9_-]{30,64}$`)
	chatPattern   = regexp.MustCompile(`^(?:-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
	secretPattern = regexp.MustCompile(`^[\x21-\x7e]{8,128}$`)
)

func DefaultSettings() Settings {
	return Settings{Kinds: append([]string(nil), DefaultKinds...), Language: "en"}
}

func validURL(raw string, https bool) bool {
	if len(raw) > 512 || strings.ContainsAny(raw, " \t\r\n") {
		return false
	}
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (!https && u.Scheme == "http")
}

// merge applies an input over the stored settings: empty secrets keep the
// stored ones, Forget clears them.
func merge(stored, in Settings) Settings {
	out := in
	out.Kinds = append([]string{}, in.Kinds...)
	if in.Webhook.Forget {
		out.Webhook.URL, out.Webhook.Secret = "", ""
	} else {
		if in.Webhook.URL == "" {
			out.Webhook.URL = stored.Webhook.URL
		}
		if in.Webhook.Secret == "" {
			out.Webhook.Secret = stored.Webhook.Secret
		}
	}
	if in.Telegram.Forget {
		out.Telegram.Token = ""
	} else if in.Telegram.Token == "" {
		out.Telegram.Token = stored.Telegram.Token
	}
	out.Webhook.Forget, out.Telegram.Forget = false, false
	if out.Telegram.API == DefaultTelegramAPI {
		out.Telegram.API = ""
	}
	return out
}

func (s Settings) Validate() error {
	seen := map[string]bool{}
	for _, k := range s.Kinds {
		if !knownKind(k) || k == KindTest || seen[k] {
			return errors.New("unknown notification kind")
		}
		seen[k] = true
	}
	switch {
	case s.Language != "en" && s.Language != "fa":
		return errors.New("notification language must be en or fa")
	case s.Webhook.URL != "" && !validURL(s.Webhook.URL, false):
		return errors.New("webhook URL must be an http(s) address without credentials")
	case s.Webhook.Secret != "" && !secretPattern.MatchString(s.Webhook.Secret):
		return errors.New("webhook secret must be 8–128 printable characters")
	case s.Webhook.Enabled && s.Webhook.URL == "":
		return errors.New("enter a webhook URL")
	case s.Telegram.Token != "" && !tokenPattern.MatchString(s.Telegram.Token):
		return errors.New("invalid Telegram bot token")
	case s.Telegram.Chat != "" && !chatPattern.MatchString(s.Telegram.Chat):
		return errors.New("Telegram chat must be a numeric ID or @channel")
	case s.Telegram.API != "" && !validURL(s.Telegram.API, true):
		return errors.New("Telegram API address must be https")
	case s.Telegram.Enabled && (s.Telegram.Token == "" || s.Telegram.Chat == ""):
		return errors.New("enter the bot token and chat")
	}
	return nil
}

func (s Settings) view() SettingsView {
	v := SettingsView{Kinds: append([]string{}, s.Kinds...), Language: s.Language}
	v.Webhook.Enabled, v.Webhook.URLSet, v.Webhook.SecretSet = s.Webhook.Enabled, s.Webhook.URL != "", s.Webhook.Secret != ""
	if u, e := url.Parse(s.Webhook.URL); e == nil && s.Webhook.URL != "" {
		v.Webhook.Host = u.Scheme + "://" + u.Host
	}
	v.Telegram.Enabled, v.Telegram.TokenSet, v.Telegram.Chat, v.Telegram.API = s.Telegram.Enabled, s.Telegram.Token != "", s.Telegram.Chat, s.Telegram.API
	return v
}

func (s Settings) external(kind string) bool {
	if !s.Webhook.Enabled && !s.Telegram.Enabled {
		return false
	}
	if kind == KindTest {
		return true
	}
	for _, k := range s.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

func (s Settings) normalized() Settings {
	if s.Kinds == nil {
		s.Kinds = append([]string(nil), DefaultKinds...)
	}
	if s.Language == "" {
		s.Language = "en"
	}
	return s
}
