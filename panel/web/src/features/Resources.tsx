import { useState } from "react";
import { Plus } from "lucide-react";
import { ResourceActions } from "./resources/ResourceActions";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Blank, PageTitle, Status, TextField } from "@/components/shared";
import { useT } from "@/lib/i18n";
import type { Inventory, Resource } from "@/lib/api";

import { ConfigurationDialog } from "./configuration/ConfigurationDialog";
import { ResourceForm } from "./resources/ResourceForm";

export function Resources({
  inventory,
  engine,
  run,
}: {
  inventory: Inventory;
  engine: "gre" | "reverse";
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const [config, setConfig] = useState<Resource>();
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<Resource>();
  const [busy, setBusy] = useState(false);
  const [renaming, setRenaming] = useState<Resource>();
  const [displayName, setDisplayName] = useState("");
  const [renameError, setRenameError] = useState("");
  const shown = inventory.resources.filter((r) =>
    engine === "gre" ? r.engine === "gre" : r.engine !== "gre",
  );
  async function remove() {
    if (!deleting) return;
    setBusy(true);
    try {
      await run({
        action: engine === "gre" ? "gre-delete" : "reverse-delete",
        service: deleting.id,
      });
      setDeleting(undefined);
    } catch {
      /* global operation feedback */
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="page-stack">
      <PageTitle
        title={t(engine)}
        description={t(engine === "gre" ? "greDesc" : "reverseDesc")}
        action={
          <Button onClick={() => setCreating(true)}>
            <Plus data-icon="inline-start" />
            {t("add")}
          </Button>
        }
      />
      {shown.length === 0 ? (
        <Card>
          <CardContent>
            <Blank onAdd={() => setCreating(true)} />
          </CardContent>
        </Card>
      ) : (
        <div className="grid items-start gap-4 md:grid-cols-2 xl:grid-cols-3">
          {shown.map((resource) => (
            <Card key={resource.id}>
              <CardHeader>
                <div className="flex items-center justify-between gap-2">
                  <CardTitle className="min-w-0 break-words">
                    {resource.name}
                  </CardTitle>
                  <Status value={resource.status} />
                </div>
                <CardDescription>
                  <span dir="ltr">
                    {resource.engine.toUpperCase()} · {resource.role}
                  </span>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <code
                  className="break-all text-xs text-muted-foreground"
                  dir="ltr"
                >
                  {resource.id}
                </code>
                {resource.interface && (
                  <p className="mt-3 text-sm">
                    <bdi>{resource.interface}</bdi>
                  </p>
                )}
              </CardContent>
              <CardFooter>
                <ResourceActions
                  resource={resource}
                  run={run}
                  onConfig={() => setConfig(resource)}
                  onRename={() => {
                    setRenaming(resource);
                    setDisplayName(resource.name);
                    setRenameError("");
                  }}
                  onDelete={() => setDeleting(resource)}
                />{" "}
              </CardFooter>
            </Card>
          ))}
        </div>
      )}
      {config && (
        <ConfigurationDialog
          resource={{
            id: config.id,
            revision: config.revision || "",
            name: config.name,
          }}
          run={run}
          onClose={() => setConfig(undefined)}
        />
      )}
      {creating && (
        <ResourceForm
          inventory={inventory}
          engine={engine}
          run={run}
          onClose={() => setCreating(false)}
        />
      )}
      <Dialog
        open={Boolean(renaming)}
        onOpenChange={(open) => !open && !busy && setRenaming(undefined)}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>{t("renameDisplay")}</DialogTitle>
            <DialogDescription>{t("renameHelp")}</DialogDescription>
          </DialogHeader>
          <form
            id="rename-resource"
            onSubmit={async (e) => {
              e.preventDefault();
              if (!renaming) return;
              setBusy(true);
              setRenameError("");
              try {
                await run({
                  action: "resource-rename",
                  resource_name: {
                    id: renaming.id,
                    revision: renaming.revision,
                    name: displayName,
                  },
                });
                setRenaming(undefined);
              } catch (e) {
                setRenameError(String(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            <TextField
              id="resource-display-name"
              label={t("name")}
              value={displayName}
              maxLength={40}
              pattern="[a-zA-Z0-9][a-zA-Z0-9_. \-]{0,39}"
              onChange={(e) => setDisplayName(e.target.value)}
            />
            {renameError && (
              <p role="alert" className="mt-3 text-sm text-destructive">
                {renameError}
              </p>
            )}
          </form>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setRenaming(undefined)}
            >
              {t("cancel")}
            </Button>
            <Button type="submit" form="rename-resource" disabled={busy}>
              {t(busy ? "working" : "save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog
        open={Boolean(deleting)}
        onOpenChange={(open) => !open && !busy && setDeleting(undefined)}
      >
        <DialogContent closeLabel={t("close")}>
          <DialogHeader>
            <DialogTitle>
              {t("delete")} · {deleting?.name}
            </DialogTitle>
            <DialogDescription>{t("reviewDesc")}</DialogDescription>
          </DialogHeader>
          <code dir="ltr">{deleting?.id}</code>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setDeleting(undefined)}
            >
              {t("cancel")}
            </Button>
            <Button variant="destructive" disabled={busy} onClick={remove}>
              {t(busy ? "working" : "delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
