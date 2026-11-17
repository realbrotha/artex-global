"use client";

import * as React from "react";

import Link from "next/link";

import { RefreshCwIcon, ScanSearchIcon, SearchIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import {
  type Analysis,
  type AssetSource,
  analysisApi,
  type CaseSource,
  hostDetailUrl,
  isHostNode,
  scheduleApi,
  wazuhApi,
} from "@/lib/wazuh-api";

import { AnalysisPanel } from "../assets/_components/analysis-panel";
import {
  type CaseFilter,
  clusterLookup,
  countHosts,
  GROUP_BYS,
  GROUP_SORTS,
  type GroupBy,
  type GroupSort,
  groupCases,
  matchesFilter,
} from "../assets/_components/case-groups";
import {
  CaseDetail,
  isCleared,
  type ListedCase,
  needsVerdict,
  severityTone,
  verdictTone,
} from "../assets/_components/case-list";
import { caseKey, GroupedCases } from "./_components/grouped-cases";
import { DetectionsOverview } from "./_components/overview";

// Keys kept from when this list was a tab of the assets page.
const GROUP_BY_KEY = "artex.detections.groupBy";
const GROUP_SORT_KEY = "artex.assets.caseHostSort";

function useStored<T extends string>(key: string, allowed: readonly T[], fallback: T): [T, (next: T) => void] {
  const [value, setValue] = React.useState<T>(fallback);
  React.useEffect(() => {
    try {
      const saved = window.localStorage.getItem(key);
      if (allowed.includes(saved as T)) setValue(saved as T);
    } catch {
      /* storage unavailable: keep the default */
    }
  }, [key, allowed]);
  const select = (next: T) => {
    setValue(next);
    try {
      window.localStorage.setItem(key, next);
    } catch {
      /* not remembered */
    }
  };
  return [value, select];
}

// Detections: what the logs say happened. The overview on top summarises
// every case candidate; the table below folds them into groups; a case line
// opens its verdict and evidence on the right.
// (Hosts and their configuration are the Infrastructure and Config checks
// screens; a host's own cases are also on its detail page.)
export default function DetectionsPage() {
  const t = useTranslations("protectedAssets");
  const [sources, setSources] = React.useState<CaseSource[] | null>(null);
  const [assets, setAssets] = React.useState<AssetSource[]>([]);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [showKnown, setShowKnown] = React.useState(false);
  const [groupBy, selectGroupBy] = useStored<GroupBy>(GROUP_BY_KEY, GROUP_BYS, "rule");
  const [sort, selectSort] = useStored<GroupSort>(GROUP_SORT_KEY, GROUP_SORTS, "risk");
  const [filter, setFilter] = React.useState<CaseFilter>({});
  const [checked, setChecked] = React.useState<Set<string>>(new Set());
  const [selected, setSelected] = React.useState<string | null>(null);
  const [analysis, setAnalysis] = React.useState<{ sourceId: string; job: Analysis } | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      setSources((await wazuhApi.cases()).sources);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("loadFailed"));
    } finally {
      setLoading(false);
    }
    // Clusters and the host total only decorate the overview: without them
    // the cases still list, under "no cluster".
    try {
      setAssets((await wazuhApi.assets()).sources);
    } catch {
      /* keep the previous graph */
    }
  }, [t]);

  React.useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 60_000);
    return () => clearInterval(timer);
  }, [load]);

  const caseSources = sources ?? [];
  const clusterOf = React.useMemo(() => clusterLookup(assets), [assets]);
  const hostsTotal = React.useMemo(() => assets.flatMap((s) => s.nodes.filter(isHostNode)).length, [assets]);
  const windowDays = Math.max(0, ...caseSources.map((s) => s.meta.window_days || 0)) || 7;

  const allCases = React.useMemo<ListedCase[]>(
    () =>
      (sources ?? []).flatMap((s) =>
        s.cases.map((c) => {
          const listed = { ...c, sourceId: s.id, sourceName: s.name };
          return listed;
        }),
      ),
    [sources],
  );
  // Live = someone may need to act: not known activity and not judged
  // normal or false positive.
  const liveCases = React.useMemo(() => allCases.filter((c) => !isCleared(c)), [allCases]);
  // What the overview summarises.
  const baseCases = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    return (showKnown ? allCases : liveCases).filter(
      (c) =>
        !q ||
        [c.actor, c.criterion, c.title, c.summary, c.entity, ...c.hosts].some((v) => v?.toLowerCase().includes(q)),
    );
  }, [allCases, liveCases, showKnown, query]);
  const counts = React.useMemo(
    () => ({
      open: baseCases.length,
      severe: baseCases.filter((c) => c.severity === "Critical" || c.severity === "High").length,
      unjudged: baseCases.filter(needsVerdict).length,
      hostsHit: countHosts(baseCases),
      hostsTotal,
    }),
    [baseCases, hostsTotal],
  );
  // What the table lists: the overview's choices applied on top.
  const listedCases = React.useMemo(
    () => baseCases.filter((c) => matchesFilter(c, filter, clusterOf)),
    [baseCases, filter, clusterOf],
  );
  const groups = React.useMemo(
    () => groupCases(listedCases, groupBy, clusterOf, sort),
    [listedCases, groupBy, clusterOf, sort],
  );
  const selectedCase = selected ? allCases.find((c) => caseKey(c) === selected) : undefined;

  // Unjudged cases wait for the next scheduled run, which judges them by itself.
  const unjudgedListed = React.useMemo(() => listedCases.filter(needsVerdict).length, [listedCases]);
  const [nextRun, setNextRun] = React.useState<string | null>(null);
  React.useEffect(() => {
    scheduleApi
      .get()
      .then((s) => setNextRun(s.schedule.enabled && s.schedule.auto_judge ? (s.next_run ?? null) : null))
      .catch(() => setNextRun(null));
  }, []);

  // Whole-connection log analysis; an empty host list means every host.
  const analyseAll = async (sourceId: string) => {
    const name = caseSources.find((s) => s.id === sourceId)?.name ?? "";
    try {
      const job = await analysisApi.start(sourceId, t("analysis.allLabel", { name }), []);
      setAnalysis({ sourceId, job });
      setSelected(null);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("analysis.startFailed"));
    }
  };

  const check = (keys: string[], on: boolean) =>
    setChecked((prev) => {
      const next = new Set(prev);
      for (const key of keys) {
        if (on) next.add(key);
        else next.delete(key);
      }
      return next;
    });

  const stampOf = (ms: number) =>
    new Date(ms).toLocaleString(undefined, { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
  const chips: { key: string; label: string; clear: CaseFilter }[] = [];
  if (filter.quick) {
    chips.push({ key: "quick", label: t(`detections.tile.${filter.quick}`), clear: { ...filter, quick: undefined } });
  }
  if (filter.criterion !== undefined) {
    chips.push({ key: "criterion", label: filter.criterion, clear: { ...filter, criterion: undefined } });
  }
  if (filter.cluster !== undefined) {
    chips.push({
      key: "cluster",
      label: filter.cluster || t("detections.noCluster"),
      clear: { ...filter, cluster: undefined },
    });
  }
  if (filter.from !== undefined && filter.to !== undefined) {
    chips.push({
      key: "time",
      label: `${filter.earlier ? "" : `${stampOf(filter.from)} `}~ ${stampOf(filter.to)}`,
      clear: { ...filter, from: undefined, to: undefined, earlier: undefined },
    });
  }

  const caseErrors = caseSources.filter((s) => s.error);
  const segment = "px-2.5 py-1.5";
  const segmentOn = "bg-primary text-primary-foreground";
  const sidePanel = "sticky top-4 flex h-[calc(100svh-6rem)] shrink-0 overflow-hidden rounded-lg border";

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl tracking-tight">{t("detections.title")}</h1>
          <p className="text-muted-foreground text-sm">{t("detections.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          {caseSources.length === 1 && (
            <Button size="sm" onClick={() => void analyseAll(caseSources[0].id)}>
              <ScanSearchIcon />
              {t("analysis.all")}
            </Button>
          )}
          {caseSources.length > 1 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button size="sm">
                  <ScanSearchIcon />
                  {t("analysis.all")}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {caseSources.map((s) => (
                  <DropdownMenuItem key={s.id} onSelect={() => void analyseAll(s.id)}>
                    {s.name}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={cn(loading && "animate-spin")} />
            {t("refresh")}
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {caseErrors.map((s) => (
        <Alert key={s.id} variant="destructive">
          <AlertDescription>{t("cases.failed", { name: s.name, error: s.error })}</AlertDescription>
        </Alert>
      ))}

      {sources === null && <Skeleton className="h-64 w-full" />}
      {sources !== null && allCases.length === 0 && (
        <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
          {caseSources.length === 0
            ? t("detections.noConnection")
            : caseSources.every((s) => !s.cases_at)
              ? t("cases.pending")
              : t("cases.empty")}
        </p>
      )}

      {allCases.length > 0 && (
        <DetectionsOverview
          cases={baseCases}
          counts={counts}
          clusterOf={clusterOf}
          windowDays={windowDays}
          filter={filter}
          onFilter={setFilter}
        />
      )}

      {allCases.length > 0 && (
        <div className="flex min-h-0 flex-1 items-start gap-4">
          <div className="grid min-w-0 flex-1 grid-cols-1 content-start gap-2">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="relative w-full sm:w-64">
                <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={t("detections.searchPlaceholder")}
                  className="h-8 pl-8 text-xs"
                />
              </div>
              <div className="flex overflow-hidden rounded-lg border">
                {GROUP_BYS.map((option) => (
                  <button
                    key={option}
                    type="button"
                    onClick={() => {
                      selectGroupBy(option);
                      setChecked(new Set());
                    }}
                    aria-pressed={groupBy === option}
                    className={cn(segment, groupBy === option ? segmentOn : "hover:bg-muted")}
                  >
                    {t(`detections.group.${option}`)}
                  </button>
                ))}
              </div>
              <div className="flex overflow-hidden rounded-lg border">
                {GROUP_SORTS.map((option) => (
                  <button
                    key={option}
                    type="button"
                    onClick={() => selectSort(option)}
                    aria-pressed={sort === option}
                    className={cn(segment, sort === option ? segmentOn : "hover:bg-muted")}
                  >
                    {t(`cases.sort.${option}`)}
                  </button>
                ))}
              </div>
              {chips.map((chip) => (
                <button
                  key={chip.key}
                  type="button"
                  onClick={() => setFilter(chip.clear)}
                  className="flex max-w-72 items-center gap-1 rounded-full border border-primary/50 bg-primary/10 px-2 py-1 hover:bg-primary/20 [&_svg]:size-3"
                >
                  <span className="truncate">{chip.label}</span>
                  <XIcon />
                </button>
              ))}
              <span className="ml-auto flex items-center gap-2 text-muted-foreground">
                {allCases.length > liveCases.length && (
                  <label className="flex items-center gap-1.5">
                    <input type="checkbox" checked={showKnown} onChange={(e) => setShowKnown(e.target.checked)} />
                    {t("cases.showKnown", { count: allCases.length - liveCases.length })}
                  </label>
                )}
                {unjudgedListed > 0 && (
                  <Link
                    href="/system/schedule"
                    className="underline decoration-dotted underline-offset-2 hover:text-foreground"
                  >
                    {nextRun
                      ? t("detections.autoJudgeAt", {
                          count: unjudgedListed,
                          when: new Date(nextRun).toLocaleString(undefined, {
                            month: "numeric",
                            day: "numeric",
                            hour: "2-digit",
                            minute: "2-digit",
                          }),
                        })
                      : t("detections.autoJudgeOff", { count: unjudgedListed })}
                  </Link>
                )}
              </span>
            </div>

            {groups.length === 0 ? (
              <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
                {t("cases.empty")}
              </p>
            ) : (
              <GroupedCases
                // Paging and open rows restart when the grouping changes.
                key={groupBy}
                groups={groups}
                by={groupBy}
                selected={selected}
                onSelect={(c) => setSelected(caseKey(c) === selected ? null : caseKey(c))}
                checked={checked}
                onCheck={check}
              />
            )}

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
              <span>{t("detections.groupCount", { groups: groups.length, cases: listedCases.length })}</span>
              {caseSources
                .filter((s) => s.cases_at && !s.error)
                .map((s) => (
                  // Short on the line; the connection and the full date are in the tooltip.
                  <span
                    key={s.id}
                    title={t("cases.generated", {
                      name: s.name,
                      alerts: s.meta.alerts,
                      days: s.meta.window_days,
                      when: new Date(s.cases_at as string).toLocaleString(),
                    })}
                  >
                    {t("cases.generatedShort", {
                      alerts: s.meta.alerts,
                      days: s.meta.window_days,
                      when: new Date(s.cases_at as string).toLocaleTimeString(undefined, {
                        hour: "2-digit",
                        minute: "2-digit",
                      }),
                    })}
                    {caseSources.length > 1 && ` (${s.name})`}
                    {s.meta.capped && ` · ${t("cases.capped")}`}
                  </span>
                ))}
            </div>
          </div>

          {selectedCase && (
            <aside className={cn(sidePanel, "w-[26rem] flex-col")}>
              <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-2 gap-y-1.5 border-b p-3">
                <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                  <span className={cn("rounded border px-1.5 py-0.5", severityTone[selectedCase.severity])}>
                    {t(`cases.severity.${selectedCase.severity}`)}
                  </span>
                  {selectedCase.verdict && (
                    <span
                      className={cn(
                        "rounded border px-1.5 py-0.5",
                        verdictTone[selectedCase.verdict.verdict],
                        selectedCase.verdict.stale && "opacity-50",
                      )}
                    >
                      {t(`cases.verdict.${selectedCase.verdict.verdict}`)}
                    </span>
                  )}
                  <span className="font-mono text-muted-foreground">{selectedCase.criterion}</span>
                </div>
                <Button
                  size="icon-xs"
                  variant="ghost"
                  aria-label={t("detections.closeDetail")}
                  onClick={() => setSelected(null)}
                >
                  <XIcon />
                </Button>
                <p className="col-span-2 font-medium text-sm">
                  {selectedCase.verdict?.title ?? selectedCase.title ?? selectedCase.criterion}
                </p>
                <p className="col-span-2 break-words text-muted-foreground text-xs">
                  {selectedCase.verdict?.explain ?? selectedCase.summary}
                </p>
                <p className="col-span-2 flex flex-wrap gap-x-2 gap-y-0.5 text-xs">
                  {selectedCase.hosts.map((host) => (
                    <Link
                      key={host}
                      href={hostDetailUrl(selectedCase.sourceId, `host:${host.split(".")[0].toLowerCase()}`)}
                      className="underline decoration-dotted underline-offset-2 hover:text-primary"
                    >
                      {host}
                    </Link>
                  ))}
                </p>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto p-3">
                <CaseDetail c={selectedCase} verdict={selectedCase.verdict} compact onCorrected={() => void load()} />
              </div>
            </aside>
          )}

          {analysis && (
            // Kept mounted behind an open case so the running job keeps polling.
            <div className={cn(sidePanel, selectedCase && "hidden")}>
              <AnalysisPanel
                sourceId={analysis.sourceId}
                initial={analysis.job}
                onClose={() => setAnalysis(null)}
                onJudged={load}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
