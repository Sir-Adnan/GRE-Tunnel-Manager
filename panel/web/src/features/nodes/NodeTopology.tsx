import { useContext } from "react";
import { Server, ArrowRight, ArrowDown, ArrowLeftRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Choice, TextField } from "@/components/shared";
import { ActionButton } from "@/components/help";
import { LocaleContext, useT } from "@/lib/i18n";

type Props = {
  choices: { value: string; label: string }[];
  entrance: string;
  destination: string;
  entranceIP: string;
  destinationIP: string;
  gre: boolean;
  onChoose: (value: string, side: "entrance" | "destination") => void;
  onAddress: (value: string, side: "entrance" | "destination") => void;
  onSwap: () => void;
};
export function NodeTopology(p: Props) {
  const t = useT(),
    locale = useContext(LocaleContext);
  return (
    <div
      className="grid items-center gap-3 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]"
      dir="ltr"
      aria-label={t("connectionTopology")}
    >
      {(["entrance", "destination"] as const).map((side, i) => (
        <div key={side} className="contents">
          {i === 1 && (
            <div className="flex items-center justify-center gap-2 md:flex-col">
              <ArrowRight
                className="hidden size-5 text-muted-foreground md:block"
                aria-hidden
              />
              <ArrowDown
                className="size-5 text-muted-foreground md:hidden"
                aria-hidden
              />
              <ActionButton
                type="button"
                variant="ghost"
                size="icon"
                label={t("swapNodes")}
                onClick={p.onSwap}
              >
                <ArrowLeftRight />
              </ActionButton>
            </div>
          )}
          <Card
            className="min-w-0 gap-4 shadow-none"
            dir={locale === "fa" ? "rtl" : "ltr"}
          >
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <span className="flex size-8 items-center justify-center rounded-lg border bg-muted">
                  <Server className="size-4" />
                </span>
                {t(side === "entrance" ? "pairEntrance" : "pairDestination")}
              </CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <Choice
                id={`pair-${side}`}
                label={t("server")}
                value={p[side]}
                onChange={(v) => p.onChoose(v, side)}
                choices={p.choices}
              />
              {(side === "entrance" || p.gre) && (
                <TextField
                  id={`pair-${side}-ip`}
                  label={t(
                    side === "entrance"
                      ? "pairEntranceIP"
                      : "pairDestinationIP",
                  )}
                  help={t("pairAddressHelp")}
                  dir="ltr"
                  value={side === "entrance" ? p.entranceIP : p.destinationIP}
                  onChange={(e) => p.onAddress(e.target.value, side)}
                  required
                />
              )}
            </CardContent>
          </Card>
        </div>
      ))}
    </div>
  );
}
