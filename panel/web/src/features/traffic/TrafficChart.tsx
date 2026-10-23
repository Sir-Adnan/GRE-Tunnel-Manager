import { useContext } from "react";
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
} from "@/components/ui/chart";
import { LocaleContext, useT } from "@/lib/i18n";
import { trafficBytes } from "@/lib/format";
import type { Sample } from "./history";

export default function TrafficChart({ samples }: { samples: Sample[] }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const time = (value: number) =>
    new Date(value).toLocaleTimeString(
      locale === "fa" ? "fa-IR-u-nu-latn" : "en-US",
      {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      },
    );
  return (
    <div dir="ltr">
      <ChartContainer
        className="h-64 w-full"
        config={{
          received: { label: t("received"), color: "var(--chart-1)" },
          sent: { label: t("sent"), color: "var(--chart-2)" },
        }}
      >
        <AreaChart
          accessibilityLayer
          data={samples}
          margin={{ left: 8, right: 12, top: 12, bottom: 0 }}
        >
          <CartesianGrid vertical={false} />
          <XAxis
            dataKey="time"
            tickFormatter={time}
            tickLine={false}
            axisLine={false}
            minTickGap={40}
          />
          <YAxis
            tickFormatter={(value: number) => trafficBytes(value, locale)}
            tickLine={false}
            axisLine={false}
            width={84}
          />
          <ChartTooltip
            content={
              <ChartTooltipContent
                labelFormatter={(_, payload) =>
                  time(Number(payload[0]?.payload?.time))
                }
                formatter={(value, name) => (
                  <div
                    className="flex w-full justify-between gap-4"
                    dir={locale === "fa" ? "rtl" : "ltr"}
                  >
                    <span>{t(String(name))}</span>
                    <bdi>{trafficBytes(Number(value), locale)}</bdi>
                  </div>
                )}
              />
            }
          />
          <ChartLegend content={<ChartLegendContent />} />
          <Area
            isAnimationActive={false}
            type="linear"
            dataKey="received"
            stroke="var(--color-received)"
            fill="var(--color-received)"
            fillOpacity={0.14}
            strokeWidth={2}
          />
          <Area
            isAnimationActive={false}
            type="linear"
            dataKey="sent"
            stroke="var(--color-sent)"
            fill="var(--color-sent)"
            fillOpacity={0.1}
            strokeWidth={2}
            strokeDasharray="5 3"
          />
        </AreaChart>
      </ChartContainer>
    </div>
  );
}
