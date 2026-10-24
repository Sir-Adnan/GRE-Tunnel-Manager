import { useEffect, useState } from "react";
import { DiscardChanges } from "@/components/DiscardChanges";
/** Drafts stay in memory. Do not persist configuration or secrets in storage. */
export function useDiscardChanges(dirty: boolean, close: () => void) {
  const [confirming, setConfirming] = useState(false);
  useEffect(() => {
    if (!dirty) return;
    const unload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    window.addEventListener("beforeunload", unload);
    return () => window.removeEventListener("beforeunload", unload);
  }, [dirty]);
  return {
    requestClose: () => (dirty ? setConfirming(true) : close()),
    confirmation: (
      <DiscardChanges
        open={confirming}
        onCancel={() => setConfirming(false)}
        onDiscard={close}
      />
    ),
  };
}
