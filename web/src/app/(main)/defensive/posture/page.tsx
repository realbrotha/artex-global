"use client";

import * as React from "react";

import Link from "next/link";

import { ListIcon, RefreshCwIcon, SearchIcon, ServerIcon, ShieldCheckIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { type AssetNode, hostDetailUrl, isHostNode, type PostureSource, postureApi, wazuhApi } from "@/lib/wazuh-api";

import { AcceptedRisksSheet } from "../assets/_components/accepted-risks-sheet";
import { Stat } from "../detections/_components/overview";
import {
  hostKey,
  matchesPosture,
  POSTURE_SORTS,
  type PostureFilter,
  type PostureSort,
  RESULTS,
  type Result,
  type Row,
  sevCounts,
  sortRows,
  stdCounts,
  stdOf,
  topHosts,
} from "./_components/posture-data";

const VIEWS = ["check", "host"] as const;
type View = (typeof VIEWS)[number];
const VIEW_KEY = "artex.posture.view";
const SORT_KEY = "artex.posture.sort";
// Rows per ranking, so the overview stays one short band above the table.
const TOP = 5;
const PAGE = 50;
const COLUMNS = "grid grid-cols-[3rem_6rem_minmax(0,1fr)_4.5rem_3.5rem_3.5rem_3.5rem_3.5rem] items-center gap-x-3";

const resultTone: Record<Result, string> = {
  fail: "text-red-600 dark:text-red-400",
  review: "text-sky-600 dark:text-sky-400",
  error: "text-amber-600 dark:text-amber-400",
  accepted: "text-violet-600 dark:text-violet-400",
};
const resultBar: Record<Result, string> = {
  fail: "bg-red-500",
  review: "bg-sky-500",
  error: "bg-amber-500",
  accepted: "bg-violet-500",
};
// Grades as config-check reports them; "" = not graded.
const sevBar: Record<string, string> = { 상: "bg-red-600", 중: "bg-orange-500", 하: "bg-sky-500" };
const sevBadge: Record<string, string> = {
  상: "border-red-600/50 bg-red-600/15 text-red-700 dark:text-red-300",
  중: "border-orange-500/50 bg-orange-500/15 text-orange-700 dark:text-orange-300",
  하: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
};

type HostRow = AssetNode & { sourceId: string };

// Node ids use the short lowercase host name ("host:web01").
const checksUrl = (sourceId: string, host: string) =>
  `${hostDetailUrl(sourceId, `host:${host.split(".")[0].toLowerCase()}`)}&tab=checks`;

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

// Config checks: is each host configured to the baseline. The overview on
// top summarises every KISA/CIS item across all hosts; the table lists the
// items; an item opens the hosts that do not meet it on the right. Evidence
// and per-target detail are on the host's own page.
export default function PosturePage() {
  const t = useTranslations("protectedAssets");
  const [sources, setSources] = React.useState<PostureSource[] | null>(null);
  const [hosts, setHosts] = React.useState<HostRow[]>([]);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<Result>("fail");
  const [filter, setFilter] = React.useState<PostureFilter>({});
  const [query, setQuery] = React.useState("");
  const [selected, setSelected] = React.useState<string | null>(null);
  const [limit, setLimit] = React.useState(PAGE);
  const [risksOpen, setRisksOpen] = React.useState(false);
  const [view, selectView] = useStored<View>(VIEW_KEY, VIEWS, "check");
  const [sort, selectSort] = useStored<PostureSort>(SORT_KEY, POSTURE_SORTS, "impact");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [p, a] = await Promise.all([postureApi.list(), wazuhApi.assets()]);
      setSources(p.sources);
      setHosts(a.sources.flatMap((s) => s.nodes.filter(isHostNode).map((n) => ({ ...n, sourceId: s.id }))));
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const rows = React.useMemo<Row[]>(
    () =>
      (sources ?? []).flatMap((s) =>
        s.checks.map((c) => ({ ...c, sourceId: s.id, key: `${s.id}/${c.std ?? ""}/${c.code}` })),
      ),
    [sources],
  );
  // Per result: how many checks have at least one such host, and how many
  // host-check pairs that is in all.
  const totals = React.useMemo(
    () =>
      Object.fromEntries(
        RESULTS.map((r) => [
          r,
          { checks: rows.filter((c) => c[r].length > 0).length, pairs: rows.reduce((n, c) => n + c[r].length, 0) },
        ]),
      ) as Record<Result, { checks: number; pairs: number }>,
    [rows],
  );
  // What the overview summarises: the selected result and the search.
  const base = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows
      .filter((c) => c[result].length > 0)
      .filter((c) => !q || [c.code, c.title, ...c[result]].some((v) => v?.toLowerCase().includes(q)));
  }, [rows, result, query]);
  const sevs = React.useMemo(() => sevCounts(base), [base]);
  const stds = React.useMemo(() => stdCounts(base), [base]);
  const worstHosts = React.useMemo(() => topHosts(base, result, TOP), [base, result]);
  // What the table lists: the overview's choices applied on top.
  const listed = React.useMemo(
    () =>
      sortRows(
        base.filter((c) => matchesPosture(c, result, filter)),
        result,
        sort,
      ),
    [base, result, filter, sort],
  );
  const listedHosts = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    return hosts
      .filter((h) => h.checks)
      .filter((h) => !q || [h.name, h.ip].some((v) => v?.toLowerCase().includes(q)))
      .sort((a, b) => (b.checks?.fail ?? 0) - (a.checks?.fail ?? 0) || a.name.localeCompare(b.name));
  }, [hosts, query]);
  const selectedRow = selected ? rows.find((c) => c.key === selected) : undefined;

  const stdLabel = (s: string) => (t.has(`checks.std.${s}`) ? t(`checks.std.${s}`) : s);
  const sevLabel = (s: string) => s || t("posture.noSev");
  const checkedHosts = (sources ?? []).reduce((n, s) => n + s.hosts, 0);
  const mostInStd = Math.max(1, ...stds.map((s) => s.checks));
  const mostOnHost = worstHosts[0]?.checks ?? 1;
  const toggle = (patch: PostureFilter) => {
    const next = { ...filter };
    for (const [key, value] of Object.entries(patch) as [keyof PostureFilter, string][]) {
      next[key] = filter[key] === value ? undefined : value;
    }
    setFilter(next);
    setLimit(PAGE);
  };

  const chips: { key: keyof PostureFilter; label: string }[] = [];
  if (filter.sev !== undefined) chips.push({ key: "sev", label: `${t("posture.col.sev")} ${sevLabel(filter.sev)}` });
  if (filter.host !== undefined) chips.push({ key: "host", label: filter.host.replace(/^[^/]*\//, "") });

  const card = "grid grid-cols-1 content-start gap-1.5 rounded-xl border bg-card px-4 py-3 shadow-xs";
  const rankRow =
    "grid w-full grid-cols-[minmax(0,1fr)_4.5rem_auto] items-center gap-x-2 rounded px-1.5 py-0.5 text-left text-xs hover:bg-muted";
  const segment = "flex items-center gap-1.5 px-2.5 py-1.5 [&_svg]:size-3.5";
  const segmentOn = "bg-primary text-primary-foreground";

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl tracking-tight">{t("posture.title")}</h1>
          <p className="text-muted-foreground text-sm">{t("posture.subtitle", { hosts: checkedHosts })}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setRisksOpen(true)}>
            <ShieldCheckIcon />
            {t("acceptedRisks.open")}
          </Button>
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
      {sources === null && !error && <Skeleton className="h-64 w-full" />}
      {sources !== null && rows.length === 0 && (
        <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
          {t("posture.empty")}
        </p>
      )}

      {rows.length > 0 && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)]">
          <div className={card}>
            <div className="-mx-2 -mt-1 flex flex-wrap items-center gap-x-1">
              {RESULTS.map((r) => (
                <Stat
                  key={r}
                  label={t(`checks.result.${r}`)}
                  value={totals[r].pairs}
                  note={t("posture.itemCount", { count: totals[r].checks })}
                  tone={totals[r].pairs > 0 ? resultTone[r] : undefined}
                  active={result === r}
                  onClick={() => {
                    setResult(r);
                    setFilter({});
                    setSelected(null);
                    setLimit(PAGE);
                  }}
                />
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground">{t("posture.sevTitle")}</p>
            <div className="flex h-6 gap-px overflow-hidden rounded-md">
              {sevs.map((s) => (
                <button
                  key={s.sev}
                  type="button"
                  aria-pressed={filter.sev === s.sev}
                  title={`${sevLabel(s.sev)} · ${t("posture.itemCount", { count: s.checks })}`}
                  onClick={() => toggle({ sev: s.sev })}
                  style={{ flexGrow: s.checks }}
                  className={cn(
                    "min-w-8 basis-0 cursor-pointer truncate px-1.5 text-left font-medium text-[11px] text-white hover:opacity-80",
                    sevBar[s.sev] ?? "bg-muted-foreground/50",
                    filter.sev !== undefined && filter.sev !== s.sev && "opacity-30",
                  )}
                >
                  {sevLabel(s.sev)} {s.checks}
                </button>
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground">{t("checks.rawNote")}</p>
          </div>

          <div className={card}>
            <p className="font-medium text-xs">{t("posture.stdTitle")}</p>
            <ul className="grid grid-cols-1">
              {stds.map((s) => (
                <li key={s.std}>
                  <button
                    type="button"
                    aria-pressed={filter.std === s.std}
                    onClick={() => toggle({ std: s.std })}
                    className={cn(rankRow, filter.std === s.std && "bg-muted ring-1 ring-primary")}
                  >
                    <span className="truncate">{stdLabel(s.std)}</span>
                    <span className="flex h-1.5 overflow-hidden rounded-full bg-muted">
                      {s.sevs.map((v) => (
                        <span
                          key={v.sev}
                          className={cn("block h-full", sevBar[v.sev] ?? "bg-muted-foreground/50")}
                          style={{ width: `${(v.checks / mostInStd) * 100}%` }}
                        />
                      ))}
                    </span>
                    <span className="text-[11px] text-muted-foreground tabular-nums">
                      {t("posture.itemShort", { count: s.checks })}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>

          <div className={card}>
            <p className="font-medium text-xs">{t("posture.hostsTitle", { result: t(`checks.result.${result}`) })}</p>
            <ul className="grid grid-cols-1">
              {worstHosts.map((h) => (
                <li key={h.key}>
                  <button
                    type="button"
                    aria-pressed={filter.host === h.key}
                    onClick={() => toggle({ host: h.key })}
                    className={cn(rankRow, filter.host === h.key && "bg-muted ring-1 ring-primary")}
                  >
                    <span className="truncate" title={h.host}>
                      {h.host}
                    </span>
                    <span className="h-1.5 overflow-hidden rounded-full bg-muted">
                      <span
                        className={cn("block h-full rounded-full", resultBar[result])}
                        style={{ width: `${(h.checks / mostOnHost) * 100}%` }}
                      />
                    </span>
                    <span className="text-[11px] text-muted-foreground tabular-nums">
                      {t("posture.itemShort", { count: h.checks })}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {rows.length > 0 && (
        <div className="flex min-h-0 flex-1 items-start gap-4">
          <div className="grid min-w-0 flex-1 grid-cols-1 content-start gap-2">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="relative w-full sm:w-64">
                <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={t(view === "check" ? "posture.searchChecks" : "searchPlaceholder")}
                  className="h-8 pl-8 text-xs"
                />
              </div>
              <div className="flex overflow-hidden rounded-lg border">
                {VIEWS.map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => selectView(v)}
                    aria-pressed={view === v}
                    className={cn(segment, view === v ? segmentOn : "hover:bg-muted")}
                  >
                    {v === "check" ? <ListIcon /> : <ServerIcon />}
                    {t(`posture.view.${v}`)}
                  </button>
                ))}
              </div>
              {view === "check" && (
                <div className="flex overflow-hidden rounded-lg border">
                  {POSTURE_SORTS.map((option) => (
                    <button
                      key={option}
                      type="button"
                      onClick={() => selectSort(option)}
                      aria-pressed={sort === option}
                      className={cn(segment, sort === option ? segmentOn : "hover:bg-muted")}
                    >
                      {t(`posture.sort.${option}`)}
                    </button>
                  ))}
                </div>
              )}
              {view === "check" && (
                <div className="flex overflow-hidden rounded-lg border">
                  {[undefined, ...stds.map((x) => x.std)].map((option) => (
                    <button
                      key={option ?? "all"}
                      type="button"
                      onClick={() => {
                        setFilter({ ...filter, std: option });
                        setLimit(PAGE);
                      }}
                      aria-pressed={filter.std === option}
                      className={cn(segment, filter.std === option ? segmentOn : "hover:bg-muted")}
                    >
                      {option === undefined ? t("checks.filterAll") : stdLabel(option)}
                    </button>
                  ))}
                </div>
              )}
              {view === "check" &&
                chips.map((chip) => (
                  <button
                    key={chip.key}
                    type="button"
                    onClick={() => setFilter({ ...filter, [chip.key]: undefined })}
                    className="flex max-w-72 items-center gap-1 rounded-full border border-primary/50 bg-primary/10 px-2 py-1 hover:bg-primary/20 [&_svg]:size-3"
                  >
                    <span className="truncate">{chip.label}</span>
                    <XIcon />
                  </button>
                ))}
              <span className="ml-auto text-[11px] text-muted-foreground tabular-nums">
                {view === "check"
                  ? t("posture.itemCount", { count: listed.length })
                  : t("posture.hostCount", { count: listedHosts.length })}
              </span>
            </div>

            {view === "check" && listed.length === 0 && (
              <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
                {t("checks.noMatch")}
              </p>
            )}
            {view === "check" && listed.length > 0 && (
              <div className="@container overflow-x-auto rounded-lg border text-xs">
                <div className="min-w-[44rem]">
                  <div className={cn(COLUMNS, "border-b bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground")}>
                    <span>{t("posture.col.sev")}</span>
                    <span>{t("posture.col.code")}</span>
                    <span>{t("posture.col.title")}</span>
                    <span>{t("posture.col.std")}</span>
                    {RESULTS.map((r) => (
                      <span key={r} className={cn("text-right", r === result && "font-medium text-foreground")}>
                        {t(`checks.result.${r}`)}
                      </span>
                    ))}
                  </div>
                  {listed.slice(0, limit).map((c) => (
                    <button
                      key={c.key}
                      type="button"
                      onClick={() => setSelected(selected === c.key ? null : c.key)}
                      aria-pressed={selected === c.key}
                      className={cn(
                        COLUMNS,
                        "w-full border-b px-3 py-1.5 text-left last:border-b-0 hover:bg-muted/60",
                        selected === c.key && "bg-primary/10 hover:bg-primary/10",
                      )}
                    >
                      <span>
                        <span
                          className={cn(
                            "rounded border px-1.5 py-0.5 text-[10px]",
                            sevBadge[c.sev ?? ""] ?? "text-muted-foreground",
                          )}
                        >
                          {sevLabel(c.sev ?? "")}
                        </span>
                      </span>
                      <span className="truncate font-mono text-[11px]">{c.code}</span>
                      <span className="truncate" title={c.title}>
                        {c.title}
                      </span>
                      <span className="truncate text-muted-foreground">{stdLabel(stdOf(c))}</span>
                      {RESULTS.map((r) => (
                        <span
                          key={r}
                          className={cn(
                            "text-right tabular-nums",
                            c[r].length === 0 ? "text-muted-foreground/50" : resultTone[r],
                            r === result && "font-medium",
                          )}
                        >
                          {c[r].length}
                        </span>
                      ))}
                    </button>
                  ))}
                  {listed.length > limit && (
                    <button
                      type="button"
                      className="w-full border-t px-3 py-2 text-center text-muted-foreground hover:bg-muted"
                      onClick={() => setLimit((n) => n + PAGE)}
                    >
                      {t("posture.more", { count: listed.length - limit })}
                    </button>
                  )}
                </div>
              </div>
            )}

            {view === "host" && (
              <div className="overflow-x-auto rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t("column.name")}</TableHead>
                      {(["fail", "review", "error", "accepted", "pass"] as const).map((r) => (
                        <TableHead key={r} className="text-right">
                          {t(`checks.result.${r}`)}
                        </TableHead>
                      ))}
                      <TableHead>{t("field.checked")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {listedHosts.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                          {hosts.length === 0 ? t("posture.empty") : t("noMatch")}
                        </TableCell>
                      </TableRow>
                    )}
                    {listedHosts.map((h) => (
                      <TableRow key={`${h.sourceId}/${h.id}`}>
                        <TableCell className="py-1.5 font-medium">
                          <Link
                            className="underline-offset-2 hover:underline"
                            href={`${hostDetailUrl(h.sourceId, h.id)}&tab=checks`}
                          >
                            {h.name}
                          </Link>
                        </TableCell>
                        {(["fail", "review", "error", "accepted", "pass"] as const).map((r) => {
                          const value = h.checks?.[r] ?? 0;
                          return (
                            <TableCell
                              key={r}
                              className={cn(
                                "py-1.5 text-right tabular-nums",
                                value > 0 && r !== "pass" && resultTone[r],
                                value === 0 && "text-muted-foreground",
                              )}
                            >
                              {value.toLocaleString()}
                            </TableCell>
                          );
                        })}
                        <TableCell className="py-1.5 font-mono text-muted-foreground text-xs">{h.checked}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>

          {view === "check" && selectedRow && (
            <aside className="sticky top-4 flex h-[calc(100svh-6rem)] w-[24rem] shrink-0 flex-col overflow-hidden rounded-lg border">
              <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-2 gap-y-1.5 border-b p-3">
                <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                  <span
                    className={cn(
                      "rounded border px-1.5 py-0.5",
                      sevBadge[selectedRow.sev ?? ""] ?? "text-muted-foreground",
                    )}
                  >
                    {sevLabel(selectedRow.sev ?? "")}
                  </span>
                  <span className="font-mono">{selectedRow.code}</span>
                  <span className="text-muted-foreground">{stdLabel(stdOf(selectedRow))}</span>
                </div>
                <Button
                  size="icon-xs"
                  variant="ghost"
                  aria-label={t("posture.closeDetail")}
                  onClick={() => setSelected(null)}
                >
                  <XIcon />
                </Button>
                <p className="col-span-2 font-medium text-sm">{selectedRow.title}</p>
                <p className="col-span-2 text-[11px] text-muted-foreground">{t("posture.detailHint")}</p>
              </div>
              <div className="grid min-h-0 flex-1 grid-cols-1 content-start gap-3 overflow-y-auto p-3 text-xs">
                {RESULTS.filter((r) => selectedRow[r].length > 0).map((r) => (
                  <div key={r} className="grid grid-cols-1 gap-1.5">
                    <p className={cn("font-medium", resultTone[r])}>
                      {t(`checks.result.${r}`)}{" "}
                      <span className="tabular-nums">{t("posture.hostCount", { count: selectedRow[r].length })}</span>
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedRow[r].map((host) => (
                        <Link
                          key={host}
                          href={checksUrl(selectedRow.sourceId, host)}
                          className={cn(
                            "rounded border bg-card px-2 py-1 hover:bg-muted",
                            filter.host === hostKey(selectedRow.sourceId, host) && "border-primary",
                          )}
                        >
                          {host}
                        </Link>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </aside>
          )}
        </div>
      )}

      <AcceptedRisksSheet
        open={risksOpen}
        onOpenChange={setRisksOpen}
        // The server re-syncs after an import; refresh once it has had time.
        onChanged={() => setTimeout(() => void load(), 4000)}
      />
    </div>
  );
}
