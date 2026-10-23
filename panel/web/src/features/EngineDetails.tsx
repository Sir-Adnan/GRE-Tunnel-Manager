import { Badge } from "@/components/ui/badge";
import { useT } from "@/lib/i18n";
import type { Component, EngineProfile } from "@/lib/api";

export function EngineDetails({
  component,
  profile,
}: {
  component: Component;
  profile?: EngineProfile;
}) {
  const t = useT();
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <dl className="flex flex-col gap-2 text-sm">
        <div className="flex flex-wrap justify-between gap-2">
          <dt className="text-muted-foreground">{t("engineVersion")}</dt>
          <dd>
            <bdi className="font-mono">{component.version || t("unknown")}</bdi>
          </dd>
        </div>
        {component.peer_version && (
          <div className="flex flex-wrap justify-between gap-2">
            <dt className="text-muted-foreground">frps</dt>
            <dd>
              <bdi className="font-mono">{component.peer_version}</bdi>
            </dd>
          </div>
        )}
        {component.installed && (
          <div className="flex flex-wrap justify-between gap-2">
            <dt className="text-muted-foreground">{t("compatibility")}</dt>
            <dd>
              <Badge variant="outline">
                {t(`compat_${component.compatibility || "unknown"}`)}
              </Badge>
            </dd>
          </div>
        )}
      </dl>
      {profile && (
        <details className="rounded-lg border p-3">
          <summary className="cursor-pointer text-sm font-medium">
            {t("adapterDetails")}
          </summary>
          <div className="mt-3 flex flex-col gap-3 text-sm leading-6">
            <p>{t(`versionPolicy_${component.id}`)}</p>
            <p>
              {t("configValidation")}: {t(`validation_${profile.validation}`)}
            </p>
            <div className="flex flex-wrap gap-2">
              {profile.features.map((feature) => (
                <Badge variant="secondary" key={feature}>
                  {t(`feature_${feature}`)}
                </Badge>
              ))}
            </div>
            <ul className="flex list-disc flex-col gap-1 ps-5 text-muted-foreground">
              {profile.limitations.map((limit) => (
                <li key={limit}>{t(`limit_${limit}`)}</li>
              ))}
            </ul>
          </div>
        </details>
      )}
    </div>
  );
}
