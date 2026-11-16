import { useContext } from "react";
import {
  Area,
  Bar,
  CartesianGrid,
  ComposedChart,
  Line,
  XAxis,
  YAxis,
} from "recharts";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart";
import { LocaleContext, useT } from "@/lib/i18n";
import { milliseconds, percent } from "./format";
import { latencyTick } from "./latency";
import type { LatencyRange, LatencyRow } from "./latency";

/** Mean latency as a line over its peak band, failed checks as bars. Loaded on demand (recharts). */
export default function LatencyChart({
  rows,
  range,
  timezone,
}: {
  rows: LatencyRow[];
  range: LatencyRange;
  timezone?: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const lossy = rows.some((row) => row.loss);
  return (
    <div dir="ltr">
      <ChartContainer
        className="latency-chart"
        config={{
          mean: { label: t("latMean"), color: "var(--chart-1)" },
          band: { label: t("latPeak"), color: "var(--chart-1)" },
          loss: { label: t("latLoss"), color: "var(--destructive)" },
        }}
      >
        <ComposedChart
          accessibilityLayer
          data={rows}
          margin={{ left: 4, right: lossy ? 4 : 12, top: 8, bottom: 0 }}
        >
          <CartesianGrid vertical={false} />
          <XAxis
            dataKey="time"
            type="number"
            scale="time"
            domain={["dataMin", "dataMax"]}
            tickFormatter={(value: number) =>
              latencyTick(value, range, locale, timezone)
            }
            tickLine={false}
            axisLine={false}
            minTickGap={36}
          />
          <YAxis
            yAxisId="ms"
            tickFormatter={(value: number) => `${value}`}
            tickLine={false}
            axisLine={false}
            width={36}
          />
          {lossy && (
            <YAxis
              yAxisId="loss"
              orientation="right"
              domain={[0, 100]}
              tickFormatter={(value: number) => `${value}%`}
              tickLine={false}
              axisLine={false}
              width={40}
            />
          )}
          <ChartTooltip
            content={
              <ChartTooltipContent
                labelFormatter={(_, payload) =>
                  latencyTick(
                    Number(payload[0]?.payload?.time),
                    range === "30d" ? "30d" : "24h",
                    locale,
                    timezone,
                  )
                }
                formatter={(value, name) => (
                  <div
                    className="flex w-full justify-between gap-4"
                    dir={locale === "fa" ? "rtl" : "ltr"}
                  >
                    <span>
                      {t(
                        name === "loss"
                          ? "latLoss"
                          : name === "band"
                            ? "latPeak"
                            : "latMean",
                      )}
                    </span>
                    <bdi className="tabular-nums">
                      {name === "loss"
                        ? percent(Number(value), locale)
                        : milliseconds(
                            Number(Array.isArray(value) ? value[1] : value),
                            locale,
                          )}
                    </bdi>
                  </div>
                )}
              />
            }
          />
          <Area
            yAxisId="ms"
            isAnimationActive={false}
            type="monotone"
            dataKey="band"
            stroke="none"
            fill="var(--color-band)"
            fillOpacity={0.18}
            connectNulls={false}
          />
          {lossy && (
            <Bar
              yAxisId="loss"
              isAnimationActive={false}
              dataKey="loss"
              fill="var(--color-loss)"
              fillOpacity={0.55}
              maxBarSize={6}
            />
          )}
          <Line
            yAxisId="ms"
            isAnimationActive={false}
            type="monotone"
            dataKey="mean"
            stroke="var(--color-mean)"
            strokeWidth={2}
            // The last hour is sparse right after a restart; dots keep lone checks visible.
            dot={range === "1h" ? { r: 2 } : false}
            connectNulls={false}
          />
        </ComposedChart>
      </ChartContainer>
    </div>
  );
}
