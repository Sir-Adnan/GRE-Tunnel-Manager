import { useCallback, useContext, useEffect, useState } from "react";
import {
  Copy,
  HelpCircle,
  Link2,
  Plus,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { api, endpoint } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { PageTitle, TextField } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardFooter,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { FieldGroup } from "@/components/ui/field";
import { Skeleton } from "@/components/ui/skeleton";
import { ActionButton, HelpTip } from "@/components/help";

import type { Node, Listing, Invitation } from "./types";
import { NodeCard } from "./NodeCard";

export function Nodes() {
  const t = useT();
  const locale = useContext(LocaleContext);
  const [list, setList] = useState<Listing>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [invitation, setInvitation] = useState<Invitation>();
  const [details, setDetails] = useState<Node>();
  const [revoking, setRevoking] = useState<Node>();
  const [help, setHelp] = useState(false);
  const [copied, setCopied] = useState(false);
  const refresh = useCallback(async () => {
    const value = await api<Listing>("nodes");
    setList(value);
    setError("");
    setDetails((old) => old && value.nodes.find((node) => node.id === old.id));
  }, []);
  useEffect(() => {
    const reload = () => {
      void refresh().catch((e) => setError(String(e)));
    };
    window.addEventListener("gtm:nodes-refresh", reload);
    return () => window.removeEventListener("gtm:nodes-refresh", reload);
  }, [refresh]);
  useEffect(() => {
    let active = true;
    api<Listing>("nodes")
      .then((value) => {
        if (active) setList(value);
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, []);
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  const date = (value?: string) =>
    value
      ? new Date(value).toLocaleString(locale === "fa" ? "fa-IR" : "en-US")
      : t("notReported");
  const closeAdd = () => {
    setAdding(false);
    setInvitation(undefined);
    setName("");
    setCopied(false);
  };
  return (
    <div className="page-stack">
      <PageTitle
        title={t("nodes")}
        description={t("nodesSubtitle")}
        action={
          <div className="flex flex-wrap gap-2">
            <ActionButton
              label={t("refresh")}
              variant="outline"
              size="icon"
              disabled={busy}
              onClick={() => void perform(refresh)}
            >
              <RefreshCw />
            </ActionButton>
            <Button variant="outline" onClick={() => setHelp(true)}>
              <HelpCircle data-icon="inline-start" />
              {t("help")}
            </Button>
            <Button
              disabled={!list?.enabled || busy}
              onClick={() => setAdding(true)}
            >
              <Plus data-icon="inline-start" />
              {t("addNode")}
            </Button>
          </div>
        }
      />
      {error && (
        <Alert variant="destructive" role="alert">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <Alert>
        <ShieldCheck />
        <AlertDescription>{t("nodesReadOnly")}</AlertDescription>
      </Alert>
      {list && !list.enabled && (
        <Card>
          <CardHeader>
            <CardTitle>{t("localReady")}</CardTitle>
            <CardDescription>{t("controllerOptional")}</CardDescription>
          </CardHeader>
          <CardFooter>
            <Button variant="outline" onClick={() => setHelp(true)}>
              {t("setupGuide")}
            </Button>
          </CardFooter>
        </Card>
      )}
      {list?.enabled && (
        <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
          <Link2 className="size-4" />
          <span>{t("controllerEndpoint")}</span>
          <bdi className="break-all" dir="ltr">
            {list.url}
          </bdi>
          <Badge variant="outline">
            {t("protocol")} {number(list.protocol, locale)}
          </Badge>
        </div>
      )}
      {!list && !error && <Skeleton className="h-60 w-full" />}
      <div className="grid min-w-0 gap-5 lg:grid-cols-2 xl:grid-cols-3">
        {list?.nodes.map((node) => (
          <NodeCard
            key={node.id}
            node={node}
            busy={busy}
            onDetails={() => setDetails(node)}
            onRevoke={() => setRevoking(node)}
          />
        ))}
      </div>
      <Dialog
        open={adding}
        onOpenChange={(open) => !open && !busy && closeAdd()}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>{t("addNode")}</DialogTitle>
            <DialogDescription>
              {t(invitation ? "inviteSecretHelp" : "nodeNameHelp")}
            </DialogDescription>
          </DialogHeader>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {!invitation ? (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void perform(async () => {
                  setInvitation(
                    await api<Invitation>("nodes/invitations", {
                      name: name.trim(),
                    }),
                  );
                });
              }}
            >
              <FieldGroup>
                <TextField
                  id="node-name"
                  label={t("name")}
                  value={name}
                  maxLength={64}
                  required
                  onChange={(e) => setName(e.target.value)}
                />
                <Button type="submit" disabled={busy || !name.trim()}>
                  {t("createInvitation")}
                </Button>
              </FieldGroup>
            </form>
          ) : (
            <div className="flex min-w-0 flex-col gap-4">
              {location.protocol === "http:" && (
                <Alert>
                  <AlertDescription>{t("invitationHttpHelp")}</AlertDescription>
                </Alert>
              )}
              <p className="text-sm">
                {t("expires")} · {date(invitation.expires)}
              </p>
              <code
                className="code-block block overflow-auto text-xs"
                dir="ltr"
              >
                bash &lt;(curl -fsSL
                https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/node-install.sh)
                --agent
              </code>
              <p className="text-xs leading-6 text-muted-foreground">
                {t("agentPackageNotice")}
              </p>
              <label className="text-sm font-medium" htmlFor="node-code">
                {t("enrollmentCode")}
              </label>
              <textarea
                id="node-code"
                readOnly
                value={invitation.code}
                dir="ltr"
                rows={5}
                className="w-full min-w-0 rounded-md border bg-background p-3 font-mono text-xs"
                onFocus={(e) => e.target.select()}
              />
              <Button
                variant="outline"
                onClick={() => {
                  void navigator.clipboard
                    ?.writeText(invitation.code)
                    .then(() => setCopied(true))
                    .catch(() => setCopied(false));
                }}
              >
                <Copy data-icon="inline-start" />
                {t(copied ? "copied" : "copy")}
              </Button>
              <p className="text-xs leading-6 text-muted-foreground">
                {t("manualCopyHelp")}
              </p>
            </div>
          )}
        </DialogContent>
      </Dialog>
      <Dialog
        open={!!revoking}
        onOpenChange={(open) => !open && setRevoking(undefined)}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>{t("revokeNode")}</DialogTitle>
            <DialogDescription>{t("revokeNodeHelp")}</DialogDescription>
          </DialogHeader>
          <p>{revoking?.name}</p>
          <Button
            variant="destructive"
            disabled={busy}
            onClick={() =>
              void perform(async () => {
                await api("nodes/revoke", {
                  id: revoking!.id,
                  revision: revoking!.revision,
                });
                setRevoking(undefined);
                await refresh();
              })
            }
          >
            {t("revokeNode")}
          </Button>
        </DialogContent>
      </Dialog>
      <Dialog
        open={!!details}
        onOpenChange={(open) => !open && setDetails(undefined)}
      >
        <DialogContent closeLabel={t("close")} className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{details?.name}</DialogTitle>
            <DialogDescription>{t("nodeDetailHelp")}</DialogDescription>
          </DialogHeader>
          <div className="flex max-h-[65dvh] min-w-0 flex-col gap-4 overflow-auto">
            <dl className="flex flex-col gap-2 text-sm">
              <dt>{t("nodeIdentity")}</dt>
              <dd className="break-all font-mono text-xs" dir="ltr">
                {details?.id}
              </dd>
              <dt>{t("os")}</dt>
              <dd>
                <bdi>{details?.inventory?.host.os || t("notReported")}</bdi>
              </dd>
              <dt>{t("capabilities")}</dt>
              <dd>
                <bdi>
                  {details?.capabilities.join(" · ") || t("notReported")}
                </bdi>
              </dd>
            </dl>
            {details?.inventory?.connections?.map((c) => (
              <div
                key={c.id}
                className="flex flex-wrap items-center justify-between gap-2 border-b py-3"
              >
                <span className="min-w-0 break-words">{c.name}</span>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">{c.engine}</Badge>
                  <Badge variant="outline">
                    <bdi>{endpoint(c.bind, c.ports)}</bdi>
                  </Badge>
                  <Badge variant="outline">
                    {t(c.status || (c.enabled ? "configured" : "disabled"))}
                  </Badge>
                </div>
              </div>
            ))}
            {details?.inventory?.resources?.map((r) => (
              <div
                key={r.id}
                className="flex flex-wrap justify-between gap-2 border-b py-3"
              >
                <bdi className="break-all">{r.name}</bdi>
                <Badge variant="outline">
                  {r.engine} · {t(r.status)}
                </Badge>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
      <Dialog open={help} onOpenChange={setHelp}>
        <DialogContent closeLabel={t("close")} className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t("nodeGuide")}</DialogTitle>
            <DialogDescription>{t("nodeGuideIntro")}</DialogDescription>
          </DialogHeader>
          <div className="flex max-h-[65dvh] min-w-0 flex-col gap-5 overflow-auto text-sm leading-7">
            {[
              ["localNode", "localGuide"],
              ["controllerRole", "controllerGuide"],
              ["remoteNode", "agentGuide"],
              ["connectionRecovery", "nodeRecoveryGuide"],
            ].map(([title, body]) => (
              <section key={title} className="flex flex-col gap-1">
                <h3 className="font-semibold">{t(title)}</h3>
                <p className="text-muted-foreground">{t(body)}</p>
              </section>
            ))}
            <code className="code-block block overflow-auto text-xs" dir="ltr">
              sudo bash node-install.sh --controller --url
              https://SERVER_IP:9443
            </code>
            <Alert>
              <AlertDescription>{t("nodeReleaseHelp")}</AlertDescription>
            </Alert>
          </div>
        </DialogContent>
      </Dialog>
      <p className="flex items-center gap-1 text-xs text-muted-foreground">
        {t("nodeRefreshHelp")}
        <HelpTip label={t("help")}>{t("nodeBoundsHelp")}</HelpTip>
      </p>
    </div>
  );
}
