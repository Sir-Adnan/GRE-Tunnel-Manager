package main

import (
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
)

// demoAccess shows the panel-renewed Let's Encrypt state in the loopback
// demo, which itself serves plain HTTP. Nothing is read from disk.
func demoAccess() certificates.Status {
	now := time.Now().UTC().Truncate(time.Hour)
	issued := now.Add(-20 * 24 * time.Hour)
	expires := issued.Add(90 * 24 * time.Hour)
	return certificates.Status{
		Protocol: "https", Host: "panel.example.com", Subject: "CN=panel.example.com", Issuer: "CN=E7,O=Let's Encrypt,C=US",
		NotBefore: issued, NotAfter: expires, Fingerprint: "3f1c9a7e52b04d6a8e21f0c7b9d4a6e1c2f8b3a5d7e9f0a1b2c3d4e5f6a7b8c9",
		Trusted: true, HostnameOK: true, Loaded: now,
		Renewal: &certificates.Renewal{
			Version: 1, Source: certificates.SourceLetsEncrypt, Host: "panel.example.com", Challenge: "http-01", AutoRenew: true,
			Issued: issued, NotAfter: expires, RenewAfter: certificates.RenewAfter(issued, expires), LastAttempt: issued,
		},
	}
}
