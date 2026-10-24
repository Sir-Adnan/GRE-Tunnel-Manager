# Remove the optional web panel

Removal is available from **Web Panel → Remove Web Panel**, the installer's interactive update/remove menu on an existing installation, or with a downloaded installer:

```bash
sudo bash panel-install.sh --uninstall
```

The script asks you to type `REMOVE`. Press Enter to cancel. `--uninstall` must be used alone; it does not download a package, install prerequisites or alter tunnel settings. The installed binary must support `gtm-panel uninstall-version` (`1`). The old published v1.3.0 binary predates this command; first upgrade to v1.3.3 using the matching installer. No release/tag is implicitly replaced by downloading the newer installer.

## Removed and retained resources

Removed after validation:

- Public panel and local panel broker services, their installer-owned unit files, and the optional Controller drop-in.
- Panel login configuration and manager-generated certificates/keys in `/etc/gre-manager-panel`.
- Controller CA, enrollment/Node registry and resolved paired-job history in `/var/lib/gre-manager-nodes`. Previously enrolled Agents need enrollment again after reinstalling a Controller; remote Agent installations are not contacted or removed.
- Panel traffic totals/checkpoints and its bounded audit files. Only `table inet gtm_panel_metrics` is removed from nftables.
- Resolved root operation receipts, panel executable and installed Bash API helper.

Preserved: GRE/reverse units and configurations, forwarding records/backups, tunnel engine binaries, the standalone forwarding boot reconciler, the manager's NAT/MSS rules, host/provider firewall policies, global settings and existing conntrack sessions. Certificates outside the panel directory remain operator-owned. The inactive, restricted `grepanel` system account/group and system journal records remain; they create no running process. OS packages are not uninstalled. Systemd normally cleans its private runtime socket directory when the broker stops. This is control-plane removal, not network-resource removal.

## Refusals and recovery

The panel/Agent installer lock prevents concurrent installer operations. An Agent on the same host blocks removal because it can share the executable, helper and receipt journal. Unknown files, symlinks, customized executable service paths or files outside the closed manifest require local inspection. There is no recursive directory deletion.

After confirmation the script stops the public process and broker, then validates the stopped Controller and exclusively checks the root operation journal. Pending confirmation, in-flight work, uncertain outcomes and `needs_attention` jobs block deletion, including after their authorization expires. Complete confirmation/recovery first. Confirmed or rolled-back connections remain as independent network resources; deleting their receipts does not delete them.

The root preparation command is CLI-only, not an HTTP/broker operation. A failed nftables inventory is not mistaken for an absent counter table. A missing nft binary blocks removal when a metrics file exists; restore the tool and retry. If preparation refuses, files remain and previously active services are restarted. Service recovery failures are reported. Removal is not atomic across systemd and files: a later disable/delete/reload failure stops and reports failure, so inspect the remaining files and service state before retrying. No success message is printed for a partial failure.

Back up private credentials, Controller identities, totals and audit if you need them later. The confirmation deliberately removes these files and creates no automatic secret copy elsewhere. To preserve identities and configurations, use **Stop Web Panel** instead of removal.
