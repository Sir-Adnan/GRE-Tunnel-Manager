# Backup and restore

Use **Backup & restore** in the web panel to download an encrypted recovery file. Keep a copy outside the server. A file stored only on the machine it protects will not help after a disk failure or reinstall.

Availability: version **v1.3.3** or later, with a matching panel executable and Bash helper.

## Create a backup

1. Open **Backup & restore → Create backup**.
2. Enter and confirm a separate backup password, with at least eight characters. A longer passphrase is preferable. Keep it separately; the application cannot recover it.
3. Choose whether to include saved traffic records, then select **Download backup**.

The `.gtm-backup` file contains managed configuration data, not an operating-system image:

| Included | Details |
| --- | --- |
| Port forwards | iptables/nftables, HAProxy and Realm records, IDs, names, destinations, weights, supported options and routing |
| GRE | Recognized keyed GRE definitions, roles, IDs, peer/local addresses and MTU |
| Reverse tunnels | Generated FRP/rathole definitions, tokens and existing Noise keys |
| Display names | GRE/reverse names, rebound to the regenerated unit fingerprint |
| Connection allocation | The monotonic connection counter |
| Optional accounting | Saved totals, cycle baselines, labels, quotas and bounded histories |

Export stops when it encounters unsupported custom GRE commands or reverse configuration. It also rejects drift between enabled relay records and existing generated files. Resolve that drift or retain a separate manual copy; an incomplete backup must not be presented as complete. The backup captures the last saved traffic sample, not bytes still in live kernel counters.

Panel accounts, sessions, TLS identity, Node/Agent certificates and registries, pairing journals, optional engine executables, external certificates, host-wide firewall policy, global tuning and legacy scripts are **not included**. These have different ownership and migration requirements. Back up each Node locally; this screen manages the panel server only. Finish pending paired operations before taking a recovery copy.

## Restore after reinstall or on another server

1. Install a matching or newer manager/panel release on the destination Linux server. Do not create new managed tunnels there yet.
2. Open **Backup & restore → Restore backup**, choose the file and enter its backup password.
3. Inspect the source, destination, resource list and external-certificate references.
4. For a new IP, enter a replacement next to the old address. Leave fields blank to keep them. IPv4 replacements must remain IPv4; the same applies to IPv6. Optional interface replacements handle changes such as `ens3` to `eth0`.
5. Select **Check changes**, inspect the updated resource summaries, then **Restore paused setup** and confirm.
6. Install missing engines from **Tunnel engines**, copy external certificates to their referenced paths, and verify local interfaces/addresses.
7. Start GRE/reverse resources with **Start & enable at boot**. Enable the forwards you need, then enable traffic collection separately.

Address replacement affects every exact matching IP in the backup, including peer and destination fields; it does not rewrite arbitrary configuration text, subnets, DNS, certificate contents or the other server. If an entrance IP changes, update its peer separately. Restoring one endpoint does not rebuild the second endpoint automatically. Port/listener and backend syntax checks still run when the restored forwards are enabled. Peer reachability must be checked on real servers.

Restore requires an **empty local managed installation**. It does not merge or overwrite existing tunnels or forwards. Existing traffic records also block accounting restore; turn off **Include traffic records** to preserve that ledger. This deliberate boundary avoids silently replacing a live setup. An unknown orphan file, running imported service or leftover boot link also stops recovery for local inspection.

All imported forwards are saved disabled. GRE/reverse units are regenerated from validated data, with no service enable/start during import. Collection stays disabled. Existing panel credentials and its listener are retained, so restoring an old backup does not change the administrator login or public panel address. Use the newly installed panel credentials after a reinstall.

Lifetime traffic totals and cycle baselines survive optional accounting recovery. Raw operating-system sample baselines are reset, because counters on the new machine cannot be compared with those on the old one. Existing advisory quotas remain advisory.

## Protection and failure handling

- Recovery envelope/schema version `1` is independent of the application release. Unknown envelope/schema versions fail closed; supported connection options are validated by the installed release.
- AES-256-GCM authenticates the payload, with a fresh 16-byte salt, 12-byte nonce and PBKDF2-HMAC-SHA256 at 600000 iterations. The backup password is separate from the panel password. There is no password reset for recovery files.
- Use HTTPS, or a trusted SSH port forward, when creating/opening backups. Explicit browser HTTP still sends the password and management requests without transport encryption.
- Session, Origin, CSRF and no-store policies apply. The public unprivileged server forwards fixed recovery actions to the local broker. Read-only Agent brokers reject them. No arbitrary path, command, unit or archive-extraction endpoint is added.
- The broker serializes operations. Export uses the same flock as terminal writers. Apply repeats validation, checks the reviewed target revision, then checks it again under the Bash mutation lock. Files are staged before publication, and each published file is atomically replaced.
- A checked publication/reload failure attempts to restore the previous empty state and remove newly created resources. Rollback failures are reported. This is not a power-loss-atomic filesystem transaction; inspect incomplete imports after an interrupted broker or machine failure.
- Accounting persistence follows configuration import. If it fails, the receipt explicitly reports that connections were restored while accounting was not. Keep the encrypted file and inspect storage; do not delete the only recovery copy.
- Limits are 128 forward records, 512 GRE/reverse resources, 20 MiB decrypted data and 28 MiB per recovery file. Normal API request limits remain unchanged; only dedicated recovery routes accept larger bodies.

Backups are downloaded on demand. No scheduled task, additional daemon, remote upload or ongoing sampling is enabled by this feature.
