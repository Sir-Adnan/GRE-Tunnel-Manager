package install

import (
	"context"
	"net"
	"path/filepath"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
)

// Status is a read-only snapshot for gtm and its menu.
type Status struct {
	Panel       bool                 `json:"panel_installed"`
	PanelState  string               `json:"panel_state,omitempty"`
	BrokerState string               `json:"broker_state,omitempty"`
	URL         string               `json:"url,omitempty"`
	Listen      string               `json:"listen,omitempty"`
	Username    string               `json:"username,omitempty"`
	Protocol    string               `json:"protocol,omitempty"`
	ConfigError string               `json:"config_error,omitempty"`
	Controller  bool                 `json:"controller"`
	Agent       bool                 `json:"agent_installed"`
	AgentState  string               `json:"agent_state,omitempty"`
	UpdateCheck bool                 `json:"update_check"`
	TwoFactor   bool                 `json:"two_factor"`
	Update      release.Check        `json:"update"`
	Certificate *certificates.Status `json:"certificate,omitempty"`
}

// ReadStatus collects the state of this host without changing anything.
func (in *Installer) ReadStatus(ctx context.Context) Status {
	l := in.Layout
	s := Status{Panel: regular(l.Unit(PanelUnit)) || regular(l.Path(ConfigFile)), Agent: in.AgentInstalled()}
	unitState := func(unit string) string {
		if !regular(l.Unit(unit)) {
			return "missing"
		}
		state, _ := in.Host.Run(ctx, "systemctl", "is-active", unit)
		if state == "" {
			state = "unknown"
		}
		return state
	}
	if s.Panel {
		s.PanelState, s.BrokerState = unitState(PanelUnit), unitState(BrokerUnit)
		s.Controller = regular(l.Path(nodesDir + "/controller.json"))
		s.UpdateCheck = regular(l.Unit(UpdateTimer)) && !in.timerDisabled(ctx, UpdateTimer)
		s.TwoFactor = regular(l.Path(TwoFactorFile))
		if c, e := config.Load(l.Path(ConfigFile)); e != nil {
			s.ConfigError = e.Error()
		} else {
			s.URL, s.Listen, s.Username, s.Protocol = c.URL(), c.Listen, c.Username, c.Scheme()
			s.Certificate = certificateStatus(l.Path(ConfigFile), c)
		}
	}
	if s.Agent {
		s.AgentState = unitState(AgentUnit)
	}
	s.Update, _ = release.LoadCheck(l.Path(release.CheckPath))
	return s
}

// CertificateHost is the name a panel certificate must cover.
func CertificateHost(c config.Config) string {
	if c.PublicHost != "" {
		return c.PublicHost
	}
	if c.PublicIP != "" {
		return c.PublicIP
	}
	host, _, _ := net.SplitHostPort(c.Listen)
	return host
}

func certificateStatus(configPath string, c config.Config) *certificates.Status {
	status := certificates.Status{Protocol: "http", Host: CertificateHost(c)}
	if c.Scheme() == "https" {
		r, e := certificates.New(func() (certificates.Source, error) {
			return certificates.Source{Certificate: c.Certificate, Key: c.PrivateKey, Host: CertificateHost(c)}, nil
		})
		if e != nil {
			status.Protocol, status.LastError = "https", e.Error()
			return &status
		}
		status = r.Status()
	}
	if renewal, e := certificates.LoadRenewal(filepath.Join(filepath.Dir(configPath), filepath.Base(certificates.RenewalPath))); e == nil {
		status.Renewal = &renewal
	}
	return &status
}
