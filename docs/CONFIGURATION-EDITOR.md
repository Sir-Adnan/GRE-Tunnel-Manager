# Configuration viewer and editor

Open the configuration action beside a connection's edit button, or **View configuration** on a GRE/reverse resource. Supported editors open directly in their editable tab. The panel operates on local manager-owned resources, not arbitrary file paths or remote Node files. This guide describes v1.3.7; see the changelog for earlier releases.

## What is displayed

| Resource | View | Editing |
| --- | --- | --- |
| HAProxy | Native configuration rendered from saved connection settings | Managed JSON or supported native text changes |
| Realm | Native TOML rendered from saved connection settings | Managed JSON or supported existing TOML values |
| iptables / nftables | Generated rules for the selected connection | Managed JSON; strict native edits for a single destination |
| GRE | Recognized network commands from its unit | View only in this release |
| FRP / rathole | Bounded recognized saved TOML, with tokens/private keys removed | View only in this release |

HAProxy/Realm normally use `/etc/gre-manager/generated/Fxxxxxx.conf` and an individual `gtm-Fxxxxxx.service`. The distribution's `/etc/haproxy/haproxy.cfg` can belong to a different operator-managed service. This editor neither imports nor replaces that unrelated global configuration.

For forwarding connections, the preview is generated from the manager's saved record, including when disabled. A status indicates whether the managed engine file matches, differs or is absent. A differing file's arbitrary contents are not returned; inspect local custom changes before applying the manager settings again. The preview does not prove what a running worker currently has loaded.

Kernel previews are **single-connection excerpts**, not a live firewall dump or a complete host ruleset. Do not execute them manually as replacements for the whole owned table. Save through the editor so all unrelated records are reloaded and retained.

Reverse projections recognize the generated single-line grammar and reject unknown structures. Comments are omitted. `auth.token`, `loadBalancer.groupKey`, `token` and `local_private_key` are masked. Downloaded redacted copies are inspection aids, not ready-to-run replacement configurations. Certificate files and private PEM material are never read by this endpoint.

## Review and apply

1. Use **Edit text** for a supported connection, or choose **Edit JSON**.
2. Change the desired values, then choose **Review**. This does not save or reload anything.
3. Inspect the regenerated output. Changing the draft or switching editor tabs invalidates this review.
4. Choose **Save & apply**. Existing record revisions, the shared full-state lock, native preflight where supported, snapshots and recovery are used.

Another edit, enable/disable or deletion invalidates the original revision. Reopen the viewer after a conflict; an old tab cannot overwrite newer settings. Applying can reload/restart a connection and interrupt VPN sessions. Normal rollback handles recognized apply/startup failures, not every remote routing or end-to-end reachability problem. Keep an independent management path when changing an active route.

## Supported text edits

The native editor imports values into the existing typed model, then re-renders and compares the complete normalized result. It is not an unrestricted native-file override. Blank lines and standalone comments are accepted for readability but not persisted.

- HAProxy: timeouts, retries, optional connection ceilings, affinity table size/expiry, balancing and server endpoint/weight/check values. Add/remove supported optional directives or targets, but retain generated process/routing syntax. Global/frontend caps and shared client/server timeouts must agree; removing both `maxconn` lines selects automatic sizing.
- Realm: supported existing network option values, log level and the first listen/remote endpoint. The first advanced edit of a legacy v1 Realm record upgrades it to the existing v3 schema and explicitly shows the added default PROXY/keepalive fields in review.
- iptables/nftables: single-destination listener/target IPs and ports, protocol, entrance interface and source policy. Update all DNAT, forward/reply, SNAT and MSS companion rules consistently. Unknown host rules, inconsistent copies, chain changes and multiple-destination edits are rejected. Use the form/JSON for larger structural changes.
- Other structural changes use managed JSON or the normal form. Unknown directives and executable hooks are rejected rather than silently ignored.

The JSON editor accepts the connection schema shown in the editor. Engine/technical identity remain fixed; one managed port is edited at a time. Options are strings, for example `"idle": "86400"` and `"fin": "30"`. Values still obey adapter limits. For batches, use the creation form; every port has its own managed record. There is no shell-command, arbitrary path, certificate upload or remote config-write field.

## Import an existing configuration

Choose **Import configuration** on a forwarding workspace, paste text or select a file (64 KiB maximum), then review the parsed connections and generated output. The default is to save them without starting. Explicit activation runs normal native preflight/application. Engines must already be installed. Existing connections are preserved; overlapping listeners and changed reviews are rejected. Import supports at most 32 one-port connections in a single shared-state transaction.

| Format | Accepted scope |
| --- | --- |
| HAProxy text | Plain TCP `frontend`/`backend` pairs, one literal-IP or wildcard bind per frontend, shared defaults, second/minute/hour/day durations, weighted targets, TCP checks and optional per-source affinity. The common `stick-table type ip size 150k expire 1h` form is supported. |
| Realm TOML | Scalar log/network options and one or more simple `[[endpoints]]` listen/remote pairs. Unknown tables, DNS/transport expressions and multi-target TOML structures require the existing form/JSON adapter. |
| Managed JSON | One object or an array for HAProxy, Realm, iptables or nftables. Use the editor's exported shape with empty IDs/revisions; saved names and options are retained. |

HAProxy global logging/chroot/user/group/daemon/stats process settings are explicitly listed as replaced by manager-owned service settings. They are never copied into executable units. Server names and section names become typed endpoint/name data; the renderer creates canonical section/server names. Unknown directives, unused backends and differing per-server shared options fail with an error. The reviewed output is authoritative: importing converts to managed connections, not a byte-for-byte adoption of a native service.

The sample multi-frontend HAProxy layout becomes separate managed services. A global `maxconn` from the source consequently applies to each imported service, not to their aggregate total; the review calls this out. Import does **not** stop or replace an existing distribution `haproxy.service` using the same ports: migrate that service deliberately before activation. It does not touch `/etc/haproxy/haproxy.cfg` or unrelated host firewall rules. FRP/rathole native imports and GRE unit imports remain outside this importer; portable backup/recovery covers recognized existing manager resources.

## Operational boundaries

Authenticated reads use `GET /api/configuration`; review uses a same-origin, CSRF-protected POST. Apply is an allowlisted job over the protected local broker and Bash API. Text is limited to 64 KiB; companion files must be bounded regular files under fixed roots. Symlinks, streams, stale revisions, unknown JSON fields and extra objects are rejected. Request/config bodies are not written to the audit log. Read/review responses do not enter the mutation job cache.

The demo renders illustrative output in-process and simulates updates. It never invokes the host Bash helper or system commands. Production rendering uses that helper, so the release must contain its matching generated `gre.sh`.
