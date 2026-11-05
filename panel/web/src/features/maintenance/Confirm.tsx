import { useState, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useT } from "@/lib/i18n";

export type ConfirmRequest = {
  title: string;
  body: ReactNode;
  action: string;
  destructive?: boolean;
  run: () => Promise<void>;
};

/** One confirmation surface for runs, deletes and reboot plans. */
export function Confirm({
  request,
  onClose,
}: {
  request?: ConfirmRequest;
  onClose: () => void;
}) {
  const t = useT();
  const [busy, setBusy] = useState(false);
  return (
    <Dialog
      open={Boolean(request)}
      onOpenChange={(open) => !open && !busy && onClose()}
    >
      <DialogContent closeLabel={t("close")} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{request?.title}</DialogTitle>
          <DialogDescription>{request?.body}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={onClose}>
            {t("cancel")}
          </Button>
          <Button
            variant={request?.destructive ? "destructive" : "default"}
            disabled={busy}
            onClick={() => {
              if (!request) return;
              setBusy(true);
              request
                .run()
                .then(onClose)
                .catch(() => undefined)
                .finally(() => setBusy(false));
            }}
          >
            {busy && (
              <Loader2 data-icon="inline-start" className="animate-spin" />
            )}
            {request?.action}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
