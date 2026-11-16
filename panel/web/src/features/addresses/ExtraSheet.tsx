// Adds an additional address in an owned unit. A separate gateway adds a
// source rule and table so replies leave the way the provider expects; the
// result shows whether the address came up and whether its route resolves.
import { useState } from "react";
import { CircleCheck, CircleX } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  NativeSelect,
  NativeSelectOption,
} from "@/components/ui/native-select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { HelpTip } from "@/components/help";
import { Segmented } from "@/components/Segmented";
import { TextField } from "@/components/shared";
import { useIsMobile } from "@/hooks/use-mobile";
import { operate } from "@/lib/api";
import { errorMessage, useT } from "@/lib/i18n";
import {
  extraProblem,
  parseExtraResult,
  withPrefix,
  type AddressReport,
} from "./model";

type Result = {
  id?: number;
  present: boolean;
  route: boolean;
  routed: boolean;
};

function Form({
  report,
  close,
  changed,
}: {
  report: AddressReport;
  close: () => void;
  changed: () => Promise<void>;
}) {
  const t = useT();
  const [address, setAddress] = useState("");
  const [iface, setIface] = useState(
    report.uplink || report.interfaces[0] || "",
  );
  const [route, setRoute] = useState<"main" | "own">("main");
  const [gateway, setGateway] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [touched, setTouched] = useState(false);
  const [result, setResult] = useState<Result>();
  const problem =
    extraProblem(address, route === "own" ? gateway : "", report.addresses) ||
    (route === "own" && !gateway.trim() ? "ipExtraNeedGateway" : "");

  async function submit() {
    setTouched(true);
    if (problem || !iface) return;
    setBusy(true);
    setError("");
    try {
      const job = await operate({
        action: "address-extra-add",
        address: {
          address: withPrefix(address),
          interface: iface,
          gateway: route === "own" ? gateway.trim() : "",
        },
      });
      setResult({
        ...parseExtraResult(String(job.result ?? "")),
        routed: route === "own",
      });
      await changed();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  if (result)
    return (
      <div className="flex min-h-0 flex-1 flex-col">
        <SheetHeader>
          <SheetTitle>{t("ipExtraAdded")}</SheetTitle>
          <SheetDescription>{t("ipExtraAddedHelp")}</SheetDescription>
        </SheetHeader>
        <div className="fw-sheet-body">
          <ul className="ip-checks">
            {(
              [
                ["ipCheckPresent", result.present],
                ...(result.routed
                  ? [["ipCheckRoute", result.route] as const]
                  : []),
              ] as const
            ).map(([key, ok]) => (
              <li key={key} data-ok={ok}>
                {ok ? (
                  <CircleCheck className="size-4 shrink-0" aria-hidden />
                ) : (
                  <CircleX className="size-4 shrink-0" aria-hidden />
                )}
                <span>{t(key)}</span>
                <span className="sr-only">
                  {t(ok ? "ipCheckOk" : "ipCheckFailed")}
                </span>
              </li>
            ))}
          </ul>
          {!(result.present && (!result.routed || result.route)) && (
            <Alert variant="destructive">
              <AlertDescription>{t("ipExtraCheckHelp")}</AlertDescription>
            </Alert>
          )}
        </div>
        <SheetFooter className="fw-sheet-footer flex-row justify-end border-t">
          <Button onClick={close}>{t("fwDone")}</Button>
        </SheetFooter>
      </div>
    );

  return (
    <form
      className="flex min-h-0 flex-1 flex-col"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <SheetHeader>
        <SheetTitle>{t("ipExtraAdd")}</SheetTitle>
        <SheetDescription>{t("ipExtraIntro")}</SheetDescription>
      </SheetHeader>
      <div className="fw-sheet-body">
        <TextField
          id="ip-extra-address"
          label={t("ipExtraAddress")}
          help={t("ipExtraAddressHelp")}
          dir="ltr"
          inputMode="decimal"
          autoComplete="off"
          spellCheck={false}
          placeholder="203.0.113.40/32"
          value={address}
          onChange={(event) => setAddress(event.target.value)}
          error={
            touched &&
            problem &&
            problem !== "ipExtraNeedGateway" &&
            problem !== "ipExtraBadGateway"
              ? t(problem)
              : ""
          }
        />
        <div className="fw-field">
          <label htmlFor="ip-extra-interface" className="text-sm font-medium">
            {t("ipExtraInterface")}
          </label>
          <NativeSelect
            id="ip-extra-interface"
            className="w-full"
            value={iface}
            onChange={(event) => setIface(event.target.value)}
          >
            {report.interfaces.map((name) => (
              <NativeSelectOption key={name} value={name}>
                {name}
              </NativeSelectOption>
            ))}
          </NativeSelect>
          {iface === report.uplink && (
            <span className="ip-caption">{t("ipUplinkInterface")}</span>
          )}
        </div>
        <div className="fw-field">
          <div className="field-label-row">
            <span className="text-sm font-medium">{t("ipExtraRoute")}</span>
            <HelpTip label={`${t("ipExtraRoute")} · ?`}>
              {t("ipExtraRouteHelp")}
            </HelpTip>
          </div>
          <Segmented
            label={t("ipExtraRoute")}
            value={route}
            onChange={(v) => setRoute(v as "main" | "own")}
            options={[
              { value: "main", label: t("ipExtraRouteMain") },
              { value: "own", label: t("ipExtraRouteOwn") },
            ]}
          />
          {route === "main" && (
            <p className="text-xs text-muted-foreground">
              {t("ipExtraRouteMainHelp")}
            </p>
          )}
        </div>
        {route === "own" && (
          <TextField
            id="ip-extra-gateway"
            label={t("ipExtraGateway")}
            dir="ltr"
            inputMode="decimal"
            autoComplete="off"
            spellCheck={false}
            placeholder={report.gateway || "203.0.113.1"}
            value={gateway}
            onChange={(event) => setGateway(event.target.value)}
            description={t("ipExtraGatewayHelp")}
            error={
              touched &&
              (problem === "ipExtraNeedGateway" ||
                problem === "ipExtraBadGateway")
                ? t(problem)
                : ""
            }
          />
        )}
        {error && (
          <Alert variant="destructive">
            <AlertDescription className="[overflow-wrap:anywhere]">
              {error}
            </AlertDescription>
          </Alert>
        )}
      </div>
      <SheetFooter className="fw-sheet-footer flex-row justify-end border-t">
        <Button type="button" variant="outline" disabled={busy} onClick={close}>
          {t("cancel")}
        </Button>
        <Button type="submit" disabled={busy || !iface}>
          {busy ? t("working") : t("ipExtraSubmit")}
        </Button>
      </SheetFooter>
    </form>
  );
}

export function ExtraSheet({
  open,
  report,
  close,
  changed,
}: {
  open: boolean;
  report: AddressReport;
  close: () => void;
  changed: () => Promise<void>;
}) {
  const t = useT();
  const mobile = useIsMobile();
  return (
    <Sheet open={open} onOpenChange={(next) => !next && close()}>
      <SheetContent
        side={mobile ? "bottom" : "right"}
        closeLabel={t("close")}
        className="fw-sheet ip-sheet gap-0"
        // Start in the address field (not on the help button, whose tip would cover it);
        // on phones focus nothing so the keyboard does not cover the form.
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          if (!mobile) document.getElementById("ip-extra-address")?.focus();
        }}
      >
        {open && <Form report={report} close={close} changed={changed} />}
      </SheetContent>
    </Sheet>
  );
}
