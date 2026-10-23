# Bounded HAProxy routing

The default is **TCP passthrough**. It forwards bytes without decrypting TLS and is the normal starting point for VPN/Reality services. Advanced routing is a separate contract from transport/health options and is limited to 16 ordered rules per connection. Native `haproxy -c` validation remains mandatory before apply.

| Mode | Routing | Encryption |
| --- | --- | --- |
| TCP passthrough | Existing default destination pool | Unchanged |
| SNI passthrough | Exact visible ClientHello SNI to one configured target | End-to-end TLS remains intact |
| HTTP | Exact Host and optional path prefix to one target | Plain HTTP |
| HTTPS termination | Same HTTP rules after local TLS termination | TLS ends at HAProxy; destinations receive plain HTTP |

First matching rule wins. Put more specific paths before general rules. Unmatched traffic uses the existing destination pool and balancing policy. Rules reference one-based positions in that connection's destination list; review the displayed endpoint after changing destinations. A routed target does not inherit automatic backup targets from the default pool. Existing health options apply to each generated backend.

Host matching is ASCII, lowercase, exact and case-insensitive at runtime. HTTP Host ports are stripped for matching. Paths are case-sensitive prefixes, with a bounded ASCII grammar and no query, regex, rewrite, header injection or arbitrary native directive. Host-only rules leave path blank. SNI mode does not accept path rules. SNI inspection waits up to five seconds for a TLS ClientHello; absent/hidden SNI, including ECH, falls back to the default pool. This is not a guarantee that a Reality deployment will tolerate SNI inspection.

## Certificates

HTTPS termination references an **operator-provisioned certificate ID**, not an arbitrary filesystem path or uploaded private key. For ID `example`, provision:

```sh
sudo install -d -o root -g root -m 700 /etc/gre-manager/certificates
sudo install -o root -g root -m 600 /secure/source/fullchain-and-key.pem /etc/gre-manager/certificates/example.pem
```

The PEM must contain the certificate chain and matching private key. IDs are 1–40 ASCII letters/digits/dashes/underscores, starting with a letter/digit. Preflight rejects symlinked certificate directories/files, wrong ownership and wrong permissions; the native engine checks the PEM. HTTPS uses TLS 1.2 or newer and advertises HTTP/1.1. This adapter does not expose HTTP/2, HTTP/3, backend TLS, automatic ACME issuance, certificate upload/download, renewal or certificate deletion. The operator manages expiry and renewal. Reapply the selected connection after replacement to load the new material.

Never use termination for a protocol requiring an opaque TLS/Reality handshake. Choose passthrough instead. The web panel's own HTTPS certificate is a separate resource. Deleting a connection or removing the panel preserves these operator certificates.

## Storage and downgrade

Routing uses manager **record v4**: the first 12 TSV fields retain their positions, field 13 carries HAProxy health/TCP options, and field 14 carries routing schema v1:

```text
1|MODE|CERTIFICATE_OR_DASH|HOST~PREFIX_OR_DASH~TARGET_POSITION,...
```

A dash represents no certificate, no prefix or an empty rule list. The closed parser validates field counts, mode, certificate ID, duplicate conditions, target bounds and injection characters in both Go and Bash. No record is evaluated as shell code. Ordinary v1/v2/v3 records retain their serialization and behavior. Terminal enable/disable, general edits and HAProxy health edits preserve the routing field; advanced routing is edited in the web panel. Old releases reject v4; downgrade requires a compatible prior snapshot. Routing is local to the panel server and is not added to the remote pair operation vocabulary.
