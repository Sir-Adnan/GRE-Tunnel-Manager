# Nodes and Agents

Agents provide **optional read-only inventory** by default. Phase 4 adds a separately enabled, leased GRE/FRP paired-create workflow in **Nodes → Connect two servers**. Existing tunnel pages still operate on the panel host. See [Paired connections](PAIRED-CONNECTIONS.md) before enabling writes.

## Choose a topology

Agents initiate outbound **HTTPS requests carrying JSON** to the dedicated Controller listener, a REST-style control API rather than gRPC or WebSocket. The normal browser HTTP/HTTPS choice is independent. Enrollment uses a hidden one-time code, then each request uses mutual TLS. Installation is one command followed by pasting that code; it is intentionally not embedded in process arguments or shell history. Once enrolled, reconnection and leaf-certificate renewal are automatic. Engines and data-plane ports still need initial local preparation; Agent enrollment alone does not install or fully administer every engine remotely.

| Deployment | What to install |
| --- | --- |
| One server, local management | Panel only. Its local Node appears automatically. |
| Panel on an entrance or destination | Panel there; optional Agents on other servers. No Agent is needed on the panel host. |
| Separate management server | Panel/Controller there; Agents on entrances and destinations. |
| Several entrances and exits | One Controller and one Agent per other managed server. Each has an independent identity. |

No third server is required. Agent availability is separate from tunnel availability. Stopping the panel or Agent does not stop confirmed tunnels. Unconfirmed paired creates expire independently in the root broker; keep that recovery service running.

## Release availability

Version **v1.3.1** includes inventory protocol 1, paired operations and optional traffic summaries. Default installers download that matching version. Earlier v1.3.0 packages predate Nodes and are rejected before services stop. Existing release assets are never overwritten.

For offline/source packages, build using [DEVELOPMENT.md](DEVELOPMENT.md) and copy `gtm-panel-v1.3.1-linux-ARCH.tar.gz` plus `SHA256SUMS` to the target. Then use the installer with `--package-dir /path/to/packages`.

Node.js, Python and Go compilers are not installed on managed servers. The Agent uses the same prebuilt Go executable; it does not serve embedded frontend assets or open an inbound port.

## Enable the Controller

Run on the updated panel host:

```bash
sudo bash node-install.sh --controller --url https://SERVER_IP:9443
```

Or fetch the matching source installer in one command:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/node-install.sh) --controller --url https://SERVER_IP:9443
```

Use root or sudo with a saved installer. The panel must already support `gtm-panel nodes protocol` (prints `1`). A domain or IPv6 address also works; IPv6 URLs require brackets. Use `--listen '[::]:9443'` for an IPv6 control listener. DNS, NAT and provider firewall configuration remain operator responsibilities. Permit the chosen TCP port on the Controller only; no firewall rules are installed automatically. The browser port and Agent control port must be different listeners.

The default dedicated listener is `0.0.0.0:9443`, TLS 1.3 only. A private CA and server certificate are created independently of browser certificates. Browser HTTP remains supported; it never enables plaintext Agent traffic. Re-running installation preserves the Controller identity, endpoint, node identities and invitations. Changing the address/listen setting is not an automatic migration; plan DNS/certificate reconfiguration and preserve the CA.

The signing key and registry are owned by `grepanel` in `/var/lib/gre-manager-nodes`, with a systemd write-path exception limited to that directory. Without `controller.json`, the extra listener does not start and local-only management remains available.

## Add another server

1. Open **Nodes → Add server**. Choose a recognizable display name (Persian and English are accepted).
2. Generate a code. It expires after ten minutes and can enroll exactly one identity. The code is displayed only in this dialog; closing it clears the browser copy.
3. Run on the other server:

   ```bash
   bash <(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/node-install.sh) --agent
   ```

   For an offline/local package, use:

   ```bash
   sudo bash node-install.sh --agent --package-dir /path/to/packages
   ```

4. Paste the code at the **hidden terminal prompt**. Do not put it in a URL, environment variable, command argument, issue or log. The Agent pins the Controller CA from this invitation before sending the secret. It generates its private key locally, submits a signed P-256 CSR and stores its issued identity privately.
5. Refresh Nodes after the first report. Reports normally arrive every 60–70 seconds. Inventory is refreshed manually. Only active paired jobs use temporary browser polling.

The default installer selects the matching v1.3.1 package and verifies its checksum/protocol before changing services.

The Agent installer targets Debian/Ubuntu with systemd, x86_64/arm64, and requires existing `curl`, `tar`, `sha256sum`, `iproute2` and `util-linux` tools. It verifies matching release checksums and protocol support, creates the restricted `greagent` account, and installs an unprivileged outbound Agent plus a separate root **read-only** Unix broker. Controller and Agent identity creation run as their respective service users via `runuser`; the installer does not chown identity files inside service-writable directories. It installs no tunnel engine and changes no tunnel configuration. Do not install an Agent on the panel host; that host is already the local Node. Updates preserve identity and validate it before stopping an existing Agent. Installation shares the panel installer lock.

## What the page shows

- **Connected**: a valid report arrived within three minutes.
- **Inventory unavailable**: Agent reached the Controller, but its local inventory read failed. A previous successful snapshot retains its original collection timestamp.
- **Connection lost**: no report for more than three minutes. Previously reported service status is historical; this is not evidence that a tunnel stopped.
- **Waiting for Agent**: enrolled identity has not reported since Controller startup.
- **Access revoked**: further reports and certificate renewal are refused, including on existing keep-alive connections.

Inventory includes the managed connection list, GRE/reverse resources, component capabilities and host summary. It does not send raw files, rathole/FRP credentials or private keys. The detail dialog is read-only and does not redirect existing tunnel operations to a remote host. Refresh retrieves the latest received snapshot; it does not force an immediate Agent scan.

Inventory and contact times are intentionally memory-only. Controller restart preserves enrollment/revocation but clears snapshots until the next Agent report. There is no database or report backlog. Optional read-only traffic summaries use a separate in-memory cache; see [Remote traffic summaries](REMOTE-TRAFFIC.md). Limits: 64 enrolled identities including revoked records, 16 unexpired invitations, 256 KiB per inventory, eight concurrent control requests, one retained snapshot per Node. Retry delays use exponential backoff capped below 65 seconds with jitter; successful reports use a 60–70 second cadence. Failed reports are replaced by a fresh scan, not queued.

## Identity lifecycle and recovery

Each Agent certificate lasts 30 days. The Agent renews it automatically when less than seven days remain, while preserving its locally generated key. Two certificate serials overlap to recover a lost renewal response; revocation blocks both. Certificate validity is checked on every request, including reused TLS connections; issued certificates cannot outlive their authority. The Controller renews its one-year server leaf certificate during TLS handshakes when less than 30 days remain. Its private CA lasts ten years; **CA rotation is an operator migration**, not automatic trust replacement. Keep system clocks accurate.

Revocation requires the current metadata revision. It does not stop services or delete tunnel files. To re-enroll after revocation, expiration, a lost initial enrollment response or identity loss:

```bash
sudo systemctl stop gre-manager-agent.service
# Retain a restricted backup of the old identity outside the active path:
sudo mv /var/lib/gre-manager-agent/identity.json /var/lib/gre-manager-agent/identity.revoked.json
# Generate a new invitation in the panel, then run the matching installer again.
sudo bash node-install.sh --agent --package-dir /path/to/packages
```

An initial enrollment response lost after Controller commit consumes the invitation; create a new one and revoke the unused identity. The installer does not reset identities automatically. Fatal identity/protocol failures stop the Agent instead of retrying indefinitely; systemd does not restart exit status 1. Fix the cause, then `sudo systemctl restart gre-manager-agent.service`. Transient connection failures retry within the running process.

Troubleshoot with:

```bash
systemctl status gre-manager-agent gre-manager-agent-broker
journalctl -u gre-manager-agent -n 30 --no-pager
systemctl status gre-manager-panel
```

Check the dedicated control port, DNS, system clock and the read-only broker socket. Read-only installations reject every task. Explicitly enabled operations accept only typed GRE/FRP tasks and private generated FRP tokens, never shell commands or arbitrary files. Local inventory can fail when managed state is invalid; repair it locally rather than treating it as an empty inventory.

Back up `controller.json` and each `identity.json` privately. Controller state contains its signing key; losing it requires re-enrollment, while restoring an old backup can restore older authorization state. Use one running Controller per state directory; a process-held file lock rejects concurrent use. Agent identities also have a process-held lock. Do not share state over network filesystems or run replicas. State writes use private temporary files, sync and rename; this is not a distributed transaction or a guarantee against every storage failure.

## Wire contract

Application SemVer and Node protocol are independent. Protocol 1 retains `inventory.read` and optionally adds `connections.pair.v1` after explicit Agent installation with `--operations`. Unknown combinations fail with a structured `{code, message}` problem. Older read-only Agents remain compatible; older Controllers reject the new capability. `gtm-panel nodes operations-version` prints `1` for matching paired-operation binaries. Do not tunnel commands through inventory fields.

| Endpoint on dedicated TLS listener | Authentication | Purpose |
| --- | --- | --- |
| `POST /v1/enroll` | Short-lived one-time secret, server CA pin | Validate CSR, allocate stable random node ID and certificate |
| `POST /v1/report` | mTLS plus active node ID/certificate serial | Validate bounded report; retain canonical known-schema inventory |
| `POST /v1/traffic` | Same active mTLS identity | Optional closed traffic-protocol-1 summary; 64 KiB / 128 counters |
| `POST /v1/rotate` | Same active identity | Issue replacement certificate with bounded overlap |
| `POST /v1/work` | Active mTLS identity advertising `connections.pair.v1` | Acknowledge a bounded result and pull one typed task |

Enrollment CSRs cannot choose their identity, SANs, usage or lifetime. The Controller assigns them. Redirects are refused. All Agent requests have a 20-second deadline; local inventory has a 15-second deadline. `protocol`, application `version`, closed `capabilities`, and either `inventory` or a fixed sanitized read failure form the report. Controller receipt/observation times are authoritative; Agent-supplied clocks are not used for freshness. Inventory revision is a SHA-256 digest; enrollment metadata uses a separate optimistic revision for revocation.

Browser APIs (`GET /api/nodes`, `POST /api/nodes/invitations`, `POST /api/nodes/revoke`) require normal administrator sessions; writes also require same-origin and CSRF checks. No invitation is returned by list calls. With browser HTTP, codes traverse that unencrypted browser connection; use a trusted private path or HTTPS when handling them. Neither the current write broker nor its socket is exposed on the control listener.

Phase 4 implements separately authorized typed jobs, expiry, bounded idempotency retention, revision checks and partial recovery. See [Paired connections](PAIRED-CONNECTIONS.md) for the precise scope. Generic SSH, shell, file editors and executable configuration endpoints remain prohibited.
