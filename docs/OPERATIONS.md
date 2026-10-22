# Operations and recovery

## Inspect before applying

```bash
bash gre.sh --version
bash gre.sh --catalog
bash gre.sh --demo
sudo bash gre.sh --validate
sudo bash gre.sh --plan
sudo bash gre.sh --doctor
sudo bash gre.sh --haproxy-status F000001
```

Read-only commands do not require root if the state file is readable. Production state normally lives in a root-only directory. `--validate`/`--plan` accept `--state-file PATH`, including a copied state file or a TSV restore point. They reject a missing/unreadable file; a new installation with no state is normal in `--doctor`.

- `--validate`: schema, backend capabilities, duplicate endpoints, direct listener loops and conflicting managed listeners. Equivalent IPv6 spellings compare equally.
- `--plan`: validation plus generated enabled configurations. No package installation, temporary files, target probes, firewall changes or service restarts. It excludes existing-resource cleanup and separate FRP instances. Output contains topology/IP addresses.
- `--doctor`: available tools, saved-state validity, forwarding switches, conntrack count/limit, GRE interfaces/MTU and service state. Missing optional tools are informational. No target traffic, bandwidth test or background monitoring is started.
- `--catalog`: implemented adapters, selection tradeoffs and explicitly unimplemented methods. No state file, root or host probes required.

Inspection exit codes: 0 for completed inspection, 1 for invalid/unreadable state or failed HAProxy socket inspection, 2 for invalid CLI arguments. Doctor's exit status reflects saved-state validity, not a guarantee that every host component is healthy. Host status commands can be unavailable or permission-limited.

## What a managed forwarding change does

1. The wizard shows the connection and obtains confirmation. An explicitly requested missing component can be installed here.
2. Under the manager lock, state is reloaded. An editor refuses to overwrite a row changed in another session. Disabled state and source-IP policy remain as selected.
3. A candidate passes record/conflict checks. Enabled connections require a local entrance IP; explicit kernel entrance interfaces must exist. IPv6 forwarding must already be configured.
4. iptables restore test, nft check and HAProxy config check run before live changes. Realm has validated data/rendering; startup remains its runtime validation. These checks cannot prove target reachability, return routing or other firewall policies.
5. The old state is snapshotted, the candidate replaces the state file atomically, and owned kernel/relay resources are reconciled. An unchanged running config and unit are retained. HAProxy additionally needs socat/timeout for local worker verification; compatible config updates reload and wait for a new worker PID, while unit/FD changes restart.
6. On failure after replacement, the previous state is restored atomically. Both kernel and relay recovery are attempted, and recovery failure is reported.

The complete operation is not atomic across kernel tables and systemd. Optional package installation and separate FRP/legacy operations are outside the managed-TSV rollback. Existing sessions can end or retain an old conntrack mapping until normal expiry; the host conntrack table is never flushed.

## Restore or investigate a failure

Use **Traffic connections → Restore point**. Select a snapshot, inspect its generated preview, then confirm. Restoration goes through the same validation/preflight/apply path and creates another snapshot. It restores managed forwarding records, not FRP instances, GRE units, optional binaries or operator certificates.

```bash
sudo journalctl -u gre-manager-forwarding.service -n 100 --no-pager
sudo journalctl -u gtm-F000001.service -n 100 --no-pager
sudo bash gre.sh --doctor
```

Replace the example connection ID with the reported ID. If rollback reports failure, inspect the saved state and logs before another change; saved desired state and live resources may differ. Do not execute a legacy backup shell file from an untrusted source.

HAProxy staged settings/status, PROXY requirements and restart cases are documented in [HAPROXY.md](HAPROXY.md). Legacy cleanup, independent global tuning journals and historical retirement/recovery are documented in [TUNING-CLEANUP.md](TUNING-CLEANUP.md). Do not restore a forwarding snapshot expecting it to roll back host tuning or a reverse-connection config.

For nftables, inspect the host's other base chains: an ACCEPT in the manager table does not override their DROP policies. For source-preserving forwarding, verify return routes. For stalls after small packets succeed, inspect path MTU and ICMP delivery on both peers.

## Rathole reverse connections

Choose **Reverse connections → rathole**. On the public entrance choose **Set up entrance**; on the private/destination host choose **Set up destination**. Match the instance name, service protocol, control TCP port and token. The generated service names append `_tcp`/`_udp`, so select the same protocol set on both peers. Copy the entrance's displayed Noise public key over a trusted channel. The private key stays in its mode-600 server config. Do not copy private keys, tokens or entire configs into public logs.

The entrance binds a control TCP listener and public TCP/UDP service port(s) to the selected local IP. Allow them explicitly in host/provider firewalls. UDP service traffic also travels through Noise over TCP; this preset has no QUIC or UDP underlay. One destination per instance; use FRP destination groups or HAProxy for the relevant load-balancing scenario.

The installer pins rathole 0.5.0 release archives with SHA-256, supports x86_64 GNU/Linux and aarch64 musl, and requires curl/unzip/sha256sum/install. It verifies the downloaded binary can execute before installation. An existing unsupported version is reported and retained. No automatic upgrades or claim that later upstream main features work with this pin.

Local files: `/etc/gre-manager/gtm-rathole-ROLE-NAME.toml` and `/etc/systemd/system/gtm-rathole-ROLE-NAME.service`. Review status with `--doctor` or `journalctl -u gtm-rathole-entrance-NAME`. A running process does not prove successful peer authentication, target reachability or packet transfer. The preset has schema validation and startup checks; rathole 0.5.0 has no separate native offline config verifier in this adapter.

**List / remove** stops/disables only the selected local service and removes its owned config/unit. A stop failure retains files for recovery. Removal on one host does not remove its peer. Recreate with a new key to rotate credentials and coordinate the destination; automatic editing/hot reload is not offered yet. FRP/rathole configs are outside TSV restore points: back them up separately with restrictive permissions.

## Remove a GRE link

The delete action lists managed connections referencing `greID`, `gre-out-ID`, `10.0.ID.0/30` or `fd00:ID::/64`. Disabled records also block deletion because re-enabling them would recreate a broken connection. Edit or delete those connections first, then confirm link removal.

This protects the default managed address/interface contracts. Custom routing, manually edited addresses, legacy rules and separate FRP endpoints are outside the dependency model. Review them before deleting. No dependent forwarding record is silently deleted.

## Deployment checks still requiring real hosts

Namespace checks cover actual GRE/NAT/relay packets in isolation. Before replacing a production installation, verify the actual two-server path, reboot readiness, systemd sandbox behavior, provider GRE/UDP policy, IPv6 RA, UFW/Docker integration, certificate renewal, large packets and long-lived sessions. Measure load with the intended TCP/UDP workload before choosing limits or claiming capacity.
