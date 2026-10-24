import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { useT } from "@/lib/i18n";

export function DiscardChanges({
  open,
  onCancel,
  onDiscard,
}: {
  open: boolean;
  onCancel: () => void;
  onDiscard: () => void;
}) {
  const t = useT();
  return (
    <Dialog open={open} onOpenChange={(next) => !next && onCancel()}>
      <DialogContent
        closeLabel={t("close")}
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          document.getElementById("keep-draft")?.focus();
        }}
      >
        <DialogHeader>
          <DialogTitle>{t("discardChanges")}</DialogTitle>
          <DialogDescription>{t("discardChangesHelp")}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button id="keep-draft" variant="outline" onClick={onCancel}>
            {t("keepEditing")}
          </Button>
          <Button variant="destructive" onClick={onDiscard}>
            {t("discard")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
