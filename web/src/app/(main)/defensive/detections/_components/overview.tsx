"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { cn } from "@/lib/utils";

import {
  type CaseFilter,
  type ClusterOf,
  clusterCounts,
  SEVERITIES,
  timeline,
  topRules,
} from "../../assets/_components/case-groups";
import type { ListedCase } from "../../assets/_components/case-list";

const DAY = 86_400_000;
// Rows per ranking, so the overview stays one short band above the table.
const ROWS = 5;
const barTone: Record<string, string> = {
  Critical: "bg-red-600",
  High: "bg-orange-500",
  Medium: "bg-amber-500",
  Low: "bg-sky-500",
  Info: "bg-muted-foreground/40",
};

interface OverviewProps {
  // Cases the overview summarises: the search and the cleared toggle applied,
  // the overview's own filter not.
  readonly cases: ListedCase[];
  readonly counts: { open: number; severe: number; unjudged: number; hostsHit: number; hostsTotal: number };
  readonly clusterOf: ClusterOf;
  readonly windowDays: number;
  readonly filter: CaseFilter;
  readonly onFilter: (next: CaseFilter) => void;
  // Page controls, at the end of the summary line rather than on a row of their own.
  readonly actions?: React.ReactNode;
}

// One number of the summary line; a button when it filters the table.
export function Stat({
  label,
  value,
  note,
  tone,
  active,
  onClick,
}: {
  readonly label: string;
  readonly value: number;
  readonly note?: string;
  readonly tone?: string;
  readonly active?: boolean;
  readonly onClick?: () => void;
}) {
  const body = (
    <>
      <span className="text-[11px] text-muted-foreground">{label}</span>
      <span className={cn("font-semibold text-base tabular-nums leading-none", tone)}>{value.toLocaleString()}</span>
      {note && <span className="text-[11px] text-muted-foreground tabular-nums">{note}</span>}
    </>
  );
  const frame = "flex items-baseline gap-1.5 rounded-md border border-transparent px-2 py-1";
  if (!onClick) return <span className={frame}>{body}</span>;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(frame, "hover:bg-muted", active && "border-primary bg-primary/10")}
    >
      {body}
    </button>
  );
}

// The whole picture before any row: how much is open, when the cases began,
// which clusters they are in and which criteria produce most of them. Tiles
// and bars all narrow the table below.
export function DetectionsOverview({ cases, counts, clusterOf, windowDays, filter, onFilter, actions }: OverviewProps) {
  const t = useTranslations("protectedAssets.detections");
  // Two-hour bars for a week or so; coarser for longer windows so bars stay visible.
  const perDay = windowDays <= 10 ? 12 : windowDays <= 30 ? 6 : 1;
  const columns = windowDays * perDay;
  // The bar under the pointer, read out in the caption line.
  const [hover, setHover] = React.useState<number | null>(null);
  const line = React.useMemo(() => {
    const end = new Date();
    end.setHours(24, 0, 0, 0);
    return timeline(cases, end.getTime() - windowDays * DAY, end.getTime(), columns);
  }, [cases, windowDays, columns]);
  const clusters = React.useMemo(() => clusterCounts(cases, clusterOf).slice(0, ROWS), [cases, clusterOf]);
  const mostInCluster = clusters[0]?.total ?? 1;
  const rules = React.useMemo(() => topRules(cases, ROWS), [cases]);
  const mostCases = rules[0]?.cases ?? 1;

  const quick = (value: CaseFilter["quick"]) =>
    onFilter({ ...filter, quick: filter.quick === value ? undefined : value });
  const clusterName = (name: string) => name || t("noCluster");
  const day = (index: number) =>
    new Date(line.start + index * DAY).toLocaleDateString(undefined, { month: "numeric", day: "numeric" });
  const hour = (ms: number) =>
    new Date(ms).toLocaleString(undefined, { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });

  const card = "grid grid-cols-1 content-start gap-1.5 rounded-xl border bg-card px-4 py-3 shadow-xs";

  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)]">
      <div className={card}>
        <div className="-mx-2 -mt-1 flex flex-wrap items-center gap-x-1">
          <Stat
            label={t("tile.open")}
            value={counts.open}
            active={!filter.quick}
            onClick={() => onFilter({ ...filter, quick: undefined })}
          />
          <Stat
            label={t("tile.severe")}
            value={counts.severe}
            tone={counts.severe > 0 ? "text-red-600 dark:text-red-400" : undefined}
            active={filter.quick === "severe"}
            onClick={() => quick("severe")}
          />
          <Stat
            label={t("tile.unjudged")}
            value={counts.unjudged}
            active={filter.quick === "unjudged"}
            onClick={() => quick("unjudged")}
          />
          <Stat
            label={t("tile.hosts")}
            value={counts.hostsHit}
            note={counts.hostsTotal > 0 ? t("tile.hostsOf", { total: counts.hostsTotal }) : undefined}
          />
          {actions && <span className="ml-auto flex items-center gap-1">{actions}</span>}
        </div>
        <p className="flex min-h-4 flex-wrap items-baseline gap-x-2 text-[11px] text-muted-foreground">
          {hover !== null && hover < line.buckets.length && (
            <>
              <span className="font-medium text-foreground tabular-nums">
                {t("time.bar", {
                  // The first bar reaches back past the window.
                  from: hover === 0 ? "…" : hour(line.start + hover * line.bucketMs),
                  to: hour(line.start + (hover + 1) * line.bucketMs),
                  count: SEVERITIES.reduce((n, sev) => n + line.buckets[hover][sev], 0),
                })}
              </span>
              <span>{t("time.click")}</span>
            </>
          )}
        </p>
        <div className="flex h-20 items-stretch">
          {line.buckets.map((bucket, index) => {
            const from = line.start + index * line.bucketMs;
            const to = from + line.bucketMs;
            const total = SEVERITIES.reduce((n, s) => n + bucket[s], 0);
            const active = filter.from === from;
            return (
              <button
                // biome-ignore lint/suspicious/noArrayIndexKey: a fixed time axis, never reordered
                key={index}
                type="button"
                disabled={total === 0}
                aria-pressed={active}
                aria-label={t("time.bar", { from: index === 0 ? "…" : hour(from), to: hour(to), count: total })}
                onMouseEnter={() => setHover(index)}
                onMouseLeave={() => setHover((current) => (current === index ? null : current))}
                onFocus={() => setHover(index)}
                onBlur={() => setHover(null)}
                onClick={() =>
                  onFilter(
                    active
                      ? { ...filter, from: undefined, to: undefined, earlier: undefined }
                      : { ...filter, from, to, earlier: index === 0 || undefined },
                  )
                }
                className={cn(
                  "flex min-w-0 flex-1 flex-col justify-end px-px",
                  // A line at each midnight, so the hourly slots read as days.
                  index % perDay === 0 && "border-l",
                  total > 0 && "cursor-pointer hover:bg-primary/15",
                  active && "bg-primary/15 ring-1 ring-primary",
                  filter.from !== undefined && !active && "opacity-40",
                )}
              >
                {SEVERITIES.filter((s) => bucket[s] > 0).map((s) => (
                  <span
                    key={s}
                    className={cn("block min-h-[3px] w-full first:rounded-t-sm", barTone[s])}
                    style={{ height: `${(bucket[s] / line.max) * 100}%` }}
                  />
                ))}
                {total === 0 && <span className="block h-px w-full bg-border" />}
              </button>
            );
          })}
        </div>
        <div
          className="grid text-[10px] text-muted-foreground"
          style={{ gridTemplateColumns: `repeat(${windowDays}, minmax(0,1fr))` }}
        >
          {Array.from({ length: windowDays }, (_, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: one label per day, in order
            <span key={index} className="truncate border-l pl-1">
              {day(index)}
            </span>
          ))}
        </div>
      </div>

      <div className={card}>
        <p className="font-medium text-xs">{t("clusters.title")}</p>
        {clusters.length === 0 && <p className="py-4 text-center text-muted-foreground text-xs">{t("empty")}</p>}
        <ul className="grid grid-cols-1">
          {clusters.map((row) => {
            const active = filter.cluster === row.cluster;
            return (
              <li key={row.cluster}>
                <button
                  type="button"
                  aria-pressed={active}
                  onClick={() => onFilter({ ...filter, cluster: active ? undefined : row.cluster })}
                  className={cn(
                    "grid w-full grid-cols-[minmax(0,1fr)_4.5rem_auto] items-center gap-x-2 rounded px-1.5 py-0.5 text-left text-xs hover:bg-muted",
                    active && "bg-muted ring-1 ring-primary",
                  )}
                >
                  <span className="truncate" title={clusterName(row.cluster)}>
                    {clusterName(row.cluster)}
                  </span>
                  <span className="col-start-3 text-[11px] text-muted-foreground tabular-nums">
                    {t("clusters.count", { count: row.total })}
                  </span>
                  <span className="-order-1 col-start-2 row-start-1 flex h-1.5 overflow-hidden rounded-full bg-muted">
                    {SEVERITIES.filter((s) => row.severities[s] > 0).map((s) => (
                      <span
                        key={s}
                        className={cn("block h-full", barTone[s])}
                        style={{ width: `${(row.severities[s] / mostInCluster) * 100}%` }}
                      />
                    ))}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </div>

      <div className={card}>
        <p className="font-medium text-xs">{t("rules.title")}</p>
        {rules.length === 0 && <p className="py-4 text-center text-muted-foreground text-xs">{t("empty")}</p>}
        <ul className="grid grid-cols-1">
          {rules.map((rule) => {
            const active = filter.criterion === rule.criterion;
            return (
              <li key={rule.criterion}>
                <button
                  type="button"
                  aria-pressed={active}
                  onClick={() => onFilter({ ...filter, criterion: active ? undefined : rule.criterion })}
                  className={cn(
                    "grid w-full grid-cols-[minmax(0,1fr)_4.5rem_auto] items-center gap-x-2 rounded px-1.5 py-0.5 text-left text-xs hover:bg-muted",
                    active && "bg-muted ring-1 ring-primary",
                  )}
                >
                  <span className="truncate" title={rule.title ?? rule.criterion}>
                    {rule.title ?? rule.criterion}
                  </span>
                  <span className="col-start-3 text-[11px] text-muted-foreground tabular-nums">
                    {t("rules.count", { cases: rule.cases, hosts: rule.hosts })}
                  </span>
                  <span className="col-start-2 row-start-1 h-1.5 overflow-hidden rounded-full bg-muted">
                    <span
                      className={cn("block h-full rounded-full", barTone[rule.worst])}
                      style={{ width: `${Math.max(3, (rule.cases / mostCases) * 100)}%` }}
                    />
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
