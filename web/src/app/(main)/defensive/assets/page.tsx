"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter } from "next/navigation";

import {
  ArrowRightIcon,
  CableIcon,
  NetworkIcon,
  RefreshCwIcon,
  ScanSearchIcon,
  SearchIcon,
  ShieldCheckIcon,
  XIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import {
  type Analysis,
  type AssetEdge,
  type AssetNode,
  type AssetSource,
  analysisApi,
  assetStatusGroup,
  type CaseSource,
  caseInvolvesHost,
  hostDetailUrl,
  isHostNode,
  wazuhApi,
} from "@/lib/wazuh-api";

import DiscoveredAssets from "../../function/assets/page";
import { AcceptedRisksSheet } from "./_components/accepted-risks-sheet";
import { AnalysisPanel } from "./_components/analysis-panel";
import { AssetGraph } from "./_components/asset-graph";
import { CaseList, isCleared, type ListedCase, needsVerdict, severityTone } from "./_components/case-list";
import { CheckTiles } from "./_components/host-checks";

const CONNECTIONS_URL = "/system/connections";
const TABS = ["graph", "list", "cases", "discovered"] as const;
type Tab = (typeof TABS)[number];

type Filter = "all" | "ok" | "down" | "missing" | "issues";
type MergedNode = AssetNode & { sourceName: string; sourceId: string; rawId: string };

const failCount = (node: AssetNode) => node.checks?.fail ?? 0;
const matchesFilter = (node: AssetNode, filter: Filter) =>
  filter === "all" || (filter === "issues" ? failCount(node) > 0 : assetStatusGroup(node) === filter);

const statusText: Record<string, string> = {
  ok: "text-emerald-600 dark:text-emerald-400",
  down: "text-red-600 dark:text-red-400",
  missing: "text-amber-600 dark:text-amber-400",
  issues: "text-red-600 dark:text-red-400",
};

// Node ids are only unique within one connection, so they are namespaced by
// connection before the graphs are drawn together.
function merge(sources: AssetSource[]): { nodes: MergedNode[]; edges: AssetEdge[] } {
  const nodes: MergedNode[] = [];
  const edges: AssetEdge[] = [];
  for (const source of sources) {
    const prefix = `${source.id}/`;
    for (const node of source.nodes) {
      nodes.push({ ...node, id: prefix + node.id, rawId: node.id, sourceId: source.id, sourceName: source.name });
    }
    for (const edge of source.edges) edges.push({ ...edge, from: prefix + edge.from, to: prefix + edge.to });
  }
  return { nodes, edges };
}

export default function ProtectedAssetsPage() {
  const t = useTranslations("protectedAssets");
  const [assets, setAssets] = React.useState<AssetSource[] | null>(null);
  const [caseSources, setCaseSources] = React.useState<CaseSource[]>([]);
  const [showKnown, setShowKnown] = React.useState(false);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [tab, setTab] = React.useState<Tab>("graph");
  // The tab lives in the URL so the dashboard can link straight to one.
  React.useEffect(() => {
    const wanted = new URLSearchParams(window.location.search).get("tab");
    if (TABS.includes(wanted as Tab)) setTab(wanted as Tab);
  }, []);
  const selectTab = (value: string) => {
    setTab(value as Tab);
    window.history.replaceState(null, "", value === "graph" ? window.location.pathname : `?tab=${value}`);
  };
  const [risksOpen, setRisksOpen] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const [query, setQuery] = React.useState("");
  const [filter, setFilter] = React.useState<Filter>("all");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [a, k] = await Promise.all([wazuhApi.assets(), wazuhApi.cases()]);
      setAssets(a.sources);
      setCaseSources(k.sources);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  React.useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 60_000);
    return () => clearInterval(timer);
  }, [load]);

  const { nodes, edges } = React.useMemo(() => merge(assets ?? []), [assets]);

  // Manual analysis started from the map's right-click menu.
  const router = useRouter();
  const [analysis, setAnalysis] = React.useState<{ sourceId: string; job: Analysis } | null>(null);
  const paneTargets = React.useMemo(() => (assets ?? []).map((s) => ({ id: s.id, label: s.name })), [assets]);
  const startAnalysis = async (nodeId: string | null, paneTarget?: string) => {
    const node = nodeId ? nodes.find((n) => n.id === nodeId) : undefined;
    const sourceId = node?.sourceId ?? paneTarget;
    if (!sourceId) return;
    // Agent names to analyse; an empty list means the whole connection.
    let targets: MergedNode[] = [];
    if (node && isHostNode(node)) targets = [node];
    else if (node) {
      const members = new Set(edges.filter((e) => e.kind === "member_of" && e.to === node.id).map((e) => e.from));
      targets = nodes.filter((n) => members.has(n.id) && n.status !== "no_agent");
    }
    const label = node
      ? node.name
      : t("analysis.allLabel", { name: paneTargets.find((p) => p.id === sourceId)?.label ?? "" });
    try {
      const job = await analysisApi.start(
        sourceId,
        label,
        targets.map((n) => n.name),
      );
      setAnalysis({ sourceId, job });
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("analysis.startFailed"));
    }
  };
  // The analysis panel lives beside the map, so the map tab is shown first.
  const analyseAll = (sourceId: string) => {
    selectTab("graph");
    void startAnalysis(null, sourceId);
  };
  const openDetail = (nodeId: string) => {
    const node = nodes.find((n) => n.id === nodeId);
    if (node) router.push(hostDetailUrl(node.sourceId, node.rawId));
  };
  const hosts = React.useMemo(() => nodes.filter(isHostNode), [nodes]);

  const counts = React.useMemo(() => {
    const c = { all: hosts.length, ok: 0, down: 0, missing: 0, issues: 0 };
    for (const h of hosts) {
      const g = assetStatusGroup(h);
      if (g !== "none") c[g] += 1;
      if (failCount(h) > 0) c.issues += 1;
    }
    return c;
  }, [hosts]);

  // Filtering keeps a matching host together with what it is attached to, so
  // a filtered map still shows where the host runs and what it belongs to.
  const visible = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q && filter === "all") return { nodes, edges, match: null };
    const match = new Set(
      hosts
        .filter((h) => matchesFilter(h, filter))
        .filter(
          (h) =>
            !q ||
            [h.name, h.ip, h.os, ...(h.roles ?? []), ...(h.groups ?? []), ...(h.services ?? [])].some((v) =>
              v?.toLowerCase().includes(q),
            ),
        )
        .map((h) => h.id),
    );
    const keep = new Set(match);
    for (const e of edges) {
      if (match.has(e.from)) keep.add(e.to);
      if (match.has(e.to) && e.kind === "runs_on") keep.add(e.from);
    }
    return {
      nodes: nodes.filter((n) => keep.has(n.id)),
      edges: edges.filter((e) => keep.has(e.from) && keep.has(e.to)),
      match,
    };
  }, [nodes, edges, hosts, query, filter]);

  const listed = React.useMemo(
    () =>
      hosts
        .filter((h) => (visible.match ? visible.match.has(h.id) : true))
        .sort((a, b) => failCount(b) - failCount(a) || a.name.localeCompare(b.name)),
    [hosts, visible],
  );

  const selected = React.useMemo(() => nodes.find((n) => n.id === selectedId) ?? null, [nodes, selectedId]);

  const allCases = React.useMemo<ListedCase[]>(
    () => caseSources.flatMap((s) => s.cases.map((c) => ({ ...c, sourceId: s.id, sourceName: s.name }))),
    [caseSources],
  );
  // Live = someone may need to act: not known activity and not judged
  // normal or false positive.
  const liveCases = React.useMemo(() => allCases.filter((c) => !isCleared(c)), [allCases]);
  const unjudged = React.useMemo(() => allCases.filter(needsVerdict), [allCases]);
  const [bulk, setBulk] = React.useState<{ done: number; total: number; failed: number } | null>(null);
  const stopBulk = React.useRef(false);
  // Judges one case at a time: each call sends that case to the model
  // provider, and a provider failure should stop the run early.
  const judgeAll = async () => {
    if (!window.confirm(t("cases.judgeAllConfirm", { count: unjudged.length }))) return;
    stopBulk.current = false;
    let failed = 0;
    const queue = [...unjudged];
    setBulk({ done: 0, total: queue.length, failed: 0 });
    for (let i = 0; i < queue.length && !stopBulk.current; i++) {
      try {
        await wazuhApi.judgeCase(queue[i].sourceId, queue[i].id);
      } catch {
        failed += 1;
        if (failed >= 3 && failed === i + 1) break; // nothing succeeds: stop
      }
      setBulk({ done: i + 1, total: queue.length, failed });
    }
    await load();
    setBulk((prev) => (prev ? { ...prev, total: prev.done } : prev));
  };
  // Cases follow the same search box as the map: host, subject, criterion or summary.
  const listedCases = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    return (showKnown ? allCases : liveCases).filter(
      (c) =>
        !q ||
        [c.actor, c.criterion, c.title, c.summary, c.entity, ...c.hosts].some((v) => v?.toLowerCase().includes(q)),
    );
  }, [allCases, liveCases, showKnown, query]);
  const hostCases = React.useMemo(() => {
    if (!selected || !isHostNode(selected)) return [];
    return liveCases.filter((c) => c.sourceId === selected.sourceId && caseInvolvesHost(c, selected.rawId));
  }, [liveCases, selected]);
  const caseErrors = caseSources.filter((s) => s.error);
  const nameOf = React.useMemo(() => new Map(nodes.map((n) => [n.id, n.name])), [nodes]);
  const relations = React.useMemo(() => {
    if (!selected) return [];
    return edges
      .filter((e) => e.from === selected.id || e.to === selected.id)
      .map((e) => ({
        key: `${e.kind}:${e.from}>${e.to}`,
        label: t(e.from === selected.id ? `relation.${e.kind}` : `relation.${e.kind}_reverse`),
        other: e.from === selected.id ? e.to : e.from,
      }));
  }, [edges, selected, t]);

  const failing = (assets ?? []).filter((s) => s.sync_error);
  const noIndexer = (assets ?? []).filter((s) => !s.indexer);
  const statusLabel = (node: AssetNode) => {
    const g = assetStatusGroup(node);
    return g === "none" ? "" : t(`status.${g}`);
  };

  const filters: { key: Filter; count: number }[] = [
    { key: "all", count: counts.all },
    { key: "ok", count: counts.ok },
    { key: "down", count: counts.down },
    { key: "missing", count: counts.missing },
    { key: "issues", count: counts.issues },
  ];

  return (
    <div className="flex flex-1 flex-col">
      <div className="flex flex-1 flex-col gap-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {failing.map((s) => (
          <Alert key={s.id} variant="destructive">
            <AlertDescription>{t("syncFailed", { name: s.name, error: s.sync_error })}</AlertDescription>
          </Alert>
        ))}
        {noIndexer.length > 0 && (
          <Alert>
            <AlertDescription>{t("noIndexer", { names: noIndexer.map((s) => s.name).join(", ") })}</AlertDescription>
          </Alert>
        )}

        <Tabs value={tab} onValueChange={selectTab} className="flex flex-1 flex-col">
          <div className="flex flex-wrap items-center gap-2">
            <TabsList>
              <TabsTrigger value="graph">{t("tabGraph")}</TabsTrigger>
              <TabsTrigger value="list">{t("tabList")}</TabsTrigger>
              <TabsTrigger value="cases">
                {t("cases.tab")}
                {liveCases.length > 0 && (
                  <span className="ml-1 rounded-full bg-red-500/15 px-1.5 text-[10px] text-red-700 tabular-nums dark:text-red-300">
                    {liveCases.length}
                  </span>
                )}
              </TabsTrigger>
              <TabsTrigger value="discovered">{t("tabDiscovered")}</TabsTrigger>
            </TabsList>
            <div className="ml-auto flex items-center gap-2">
              {/* Whole-fleet analysis: the same action as right-clicking empty map space. */}
              {paneTargets.length === 1 && (
                <Button size="sm" onClick={() => analyseAll(paneTargets[0].id)}>
                  <ScanSearchIcon />
                  {t("analysis.all")}
                </Button>
              )}
              {paneTargets.length > 1 && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button size="sm">
                      <ScanSearchIcon />
                      {t("analysis.all")}
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    {paneTargets.map((target) => (
                      <DropdownMenuItem key={target.id} onSelect={() => analyseAll(target.id)}>
                        {target.label}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
              <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
                <RefreshCwIcon className={cn(loading && "animate-spin")} />
                {t("refresh")}
              </Button>
              <Button variant="outline" size="sm" onClick={() => setRisksOpen(true)}>
                <ShieldCheckIcon />
                {t("acceptedRisks.open")}
              </Button>
              <Button asChild variant="outline" size="sm">
                <Link href={CONNECTIONS_URL}>
                  <CableIcon />
                  {t("manageConnections")}
                </Link>
              </Button>
            </div>
          </div>

          {tab !== "discovered" && assets !== null && assets.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              {filters.map((f) => (
                <button
                  key={f.key}
                  type="button"
                  onClick={() => setFilter(f.key)}
                  className={cn(
                    "flex items-baseline gap-2 rounded-lg border px-3 py-1.5 text-left transition-colors",
                    filter === f.key ? "border-primary bg-primary/5" : "hover:bg-muted/50",
                  )}
                >
                  <span className="text-muted-foreground text-xs">{t(`filter.${f.key}`)}</span>
                  <span className={cn("font-semibold tabular-nums", statusText[f.key])}>{f.count}</span>
                </button>
              ))}
              <div className="relative ml-auto w-full sm:w-64">
                <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={t("searchPlaceholder")}
                  className="pl-8"
                />
              </div>
            </div>
          )}

          {tab !== "discovered" && assets === null && <Skeleton className="h-96 w-full" />}
          {tab !== "discovered" && assets?.length === 0 && (
            <div className="flex flex-1 flex-col items-center justify-center gap-3 rounded-lg border border-dashed p-10 text-center">
              <NetworkIcon className="size-8 text-muted-foreground" />
              <p className="font-medium">{t("emptyTitle")}</p>
              <p className="max-w-md text-muted-foreground text-sm">{t("emptyDescription")}</p>
              <Button asChild>
                <Link href={CONNECTIONS_URL}>
                  <CableIcon />
                  {t("addConnection")}
                </Link>
              </Button>
            </div>
          )}
          {assets !== null && assets.length > 0 && (
            <>
              <TabsContent value="graph" className="flex flex-1 flex-col gap-2">
                <div className="flex h-[calc(100svh-12rem)] min-h-[520px] overflow-hidden rounded-lg border">
                  <div className="min-w-0 flex-1">
                    <AssetGraph
                      nodes={visible.nodes}
                      edges={visible.edges}
                      selectedId={selectedId}
                      onSelect={setSelectedId}
                      onAnalyze={(nodeId, paneTarget) => void startAnalysis(nodeId, paneTarget)}
                      onOpenDetail={openDetail}
                      paneTargets={paneTargets}
                    />
                  </div>
                  {analysis && (
                    <AnalysisPanel
                      sourceId={analysis.sourceId}
                      initial={analysis.job}
                      onClose={() => setAnalysis(null)}
                      onJudged={load}
                    />
                  )}
                  {!analysis && selected && (
                    <aside className="w-80 shrink-0 overflow-y-auto border-l bg-card p-4 text-sm">
                      <div className="flex items-start gap-2">
                        <div className="min-w-0 flex-1">
                          <p className="truncate font-semibold">{selected.name}</p>
                          <p className="text-muted-foreground text-xs">{t(`kind.${selected.kind}`)}</p>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          onClick={() => setSelectedId(null)}
                          aria-label={t("close")}
                        >
                          <XIcon />
                        </Button>
                      </div>
                      {isHostNode(selected) && (
                        <Button asChild size="sm" variant="outline" className="mt-3 w-full">
                          <Link href={hostDetailUrl(selected.sourceId, selected.rawId)}>
                            {t("host.detail")}
                            <ArrowRightIcon />
                          </Link>
                        </Button>
                      )}
                      <dl className="mt-3 grid grid-cols-1 gap-2.5">
                        {(
                          [
                            ["status", statusLabel(selected)],
                            ["publicIp", selected.public_ip],
                            ["ip", selected.ip],
                            ["os", selected.os],
                            ["virt", selected.virt],
                            ["lastSeen", selected.last_seen ? new Date(selected.last_seen).toLocaleString() : ""],
                            ["checked", selected.checked],
                            ["members", selected.members ? String(selected.members) : ""],
                            ["connection", selected.sourceName],
                          ] as const
                        )
                          .filter(([, value]) => value)
                          .map(([key, value]) => (
                            <div key={key}>
                              <dt className="text-[11px] text-muted-foreground">{t(`field.${key}`)}</dt>
                              <dd className="break-words">{value}</dd>
                            </div>
                          ))}
                        {(
                          [
                            ["roles", selected.roles],
                            ["services", selected.services],
                            ["groups", selected.groups],
                          ] as const
                        )
                          .filter(([, list]) => list?.length)
                          .map(([key, list]) => (
                            <div key={key}>
                              <dt className="text-[11px] text-muted-foreground">{t(`field.${key}`)}</dt>
                              <dd className="mt-1 flex flex-wrap gap-1">
                                {list?.map((item) => (
                                  <Badge key={item} variant="secondary">
                                    {item}
                                  </Badge>
                                ))}
                              </dd>
                            </div>
                          ))}
                        {selected.checks && (
                          <div>
                            <dt className="text-[11px] text-muted-foreground">{t("checks.title")}</dt>
                            <dd className="mt-1">
                              <CheckTiles checks={selected.checks} />
                            </dd>
                          </div>
                        )}
                        {hostCases.length > 0 && (
                          <div>
                            <dt className="text-[11px] text-muted-foreground">
                              {t("cases.hostTitle", { count: hostCases.length })}
                            </dt>
                            <dd className="mt-1 grid grid-cols-1 gap-1 text-xs">
                              {hostCases.slice(0, 3).map((c) => (
                                <p key={c.id} className="truncate">
                                  <span
                                    className={cn(
                                      "mr-1 rounded border px-1 py-0.5 text-[10px]",
                                      severityTone[c.severity],
                                    )}
                                  >
                                    {t(`cases.severity.${c.severity}`)}
                                  </span>
                                  {c.verdict?.title ?? c.title ?? c.criterion}
                                </p>
                              ))}
                            </dd>
                          </div>
                        )}
                        {relations.length > 0 && (
                          <div>
                            <dt className="text-[11px] text-muted-foreground">{t("field.relations")}</dt>
                            <dd className="mt-1 grid gap-1">
                              {relations.map((r) => (
                                <button
                                  key={r.key}
                                  type="button"
                                  onClick={() => setSelectedId(r.other)}
                                  className="truncate rounded border px-2 py-1 text-left text-xs hover:bg-muted"
                                >
                                  <span className="text-muted-foreground">{r.label}</span> {nameOf.get(r.other)}
                                </button>
                              ))}
                            </dd>
                          </div>
                        )}
                      </dl>
                    </aside>
                  )}
                </div>
              </TabsContent>

              <TabsContent value="list">
                <div className="overflow-x-auto rounded-lg border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        {(["name", "kind", "status", "checks", "roles", "services", "ip", "os"] as const).map((col) => (
                          <TableHead key={col}>{t(`column.${col}`)}</TableHead>
                        ))}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {listed.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={8} className="py-8 text-center text-muted-foreground">
                            {t("noMatch")}
                          </TableCell>
                        </TableRow>
                      )}
                      {listed.map((h) => (
                        <TableRow key={h.id}>
                          <TableCell className="font-medium">
                            <Link
                              className="underline-offset-2 hover:underline"
                              href={hostDetailUrl(h.sourceId, h.rawId)}
                            >
                              {h.name}
                            </Link>
                          </TableCell>
                          <TableCell>{t(`kind.${h.kind}`)}</TableCell>
                          <TableCell className={statusText[assetStatusGroup(h)]}>{statusLabel(h)}</TableCell>
                          <TableCell className="whitespace-nowrap tabular-nums">
                            {h.checks ? (
                              <>
                                <span className={cn(h.checks.fail > 0 && "font-medium text-red-600 dark:text-red-400")}>
                                  {t("checks.failCount", { count: h.checks.fail })}
                                </span>
                                <span className="text-muted-foreground">
                                  {" · "}
                                  {t("checks.reviewCount", { count: h.checks.review })}
                                </span>
                              </>
                            ) : (
                              <span className="text-muted-foreground">{t("checks.none")}</span>
                            )}
                          </TableCell>
                          <TableCell>{h.roles?.join(", ")}</TableCell>
                          <TableCell>{h.services?.join(", ")}</TableCell>
                          <TableCell className="font-mono text-xs">
                            {h.ip}
                            {h.public_ip && h.public_ip !== h.ip && (
                              <span className="block text-sky-700 dark:text-sky-300">{h.public_ip}</span>
                            )}
                          </TableCell>
                          <TableCell>{h.os}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </TabsContent>

              <TabsContent value="cases" className="grid grid-cols-1 gap-3">
                {caseErrors.map((s) => (
                  <Alert key={s.id} variant="destructive">
                    <AlertDescription>{t("cases.failed", { name: s.name, error: s.error })}</AlertDescription>
                  </Alert>
                ))}
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-muted-foreground text-xs">
                  {caseSources
                    .filter((s) => s.cases_at && !s.error)
                    .map((s) => (
                      <span key={s.id}>
                        {t("cases.generated", {
                          name: s.name,
                          alerts: s.meta.alerts,
                          days: s.meta.window_days,
                          when: new Date(s.cases_at as string).toLocaleString(),
                        })}
                        {s.meta.capped && ` · ${t("cases.capped")}`}
                      </span>
                    ))}
                  {unjudged.length > 0 && !bulk && (
                    <Button size="xs" variant="outline" onClick={() => void judgeAll()}>
                      {t("cases.judgeAll", { count: unjudged.length })}
                    </Button>
                  )}
                  {bulk && bulk.done < bulk.total && (
                    <span className="flex items-center gap-2">
                      {t("cases.judgeProgress", { done: bulk.done, total: bulk.total })}
                      <Button
                        size="xs"
                        variant="outline"
                        onClick={() => {
                          stopBulk.current = true;
                        }}
                      >
                        {t("cases.judgeStop")}
                      </Button>
                    </span>
                  )}
                  {bulk && bulk.done >= bulk.total && (
                    <span>{t("cases.judgeDone", { done: bulk.done - bulk.failed, failed: bulk.failed })}</span>
                  )}
                  {allCases.length > liveCases.length && (
                    <label className="ml-auto flex items-center gap-1.5">
                      <input type="checkbox" checked={showKnown} onChange={(e) => setShowKnown(e.target.checked)} />
                      {t("cases.showKnown", { count: allCases.length - liveCases.length })}
                    </label>
                  )}
                </div>
                {listedCases.length === 0 ? (
                  <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
                    {caseSources.every((s) => !s.cases_at) ? t("cases.pending") : t("cases.empty")}
                  </p>
                ) : (
                  <CaseList cases={listedCases} onJudged={() => void load()} />
                )}
              </TabsContent>
            </>
          )}

          <TabsContent value="discovered">
            <DiscoveredAssets />
          </TabsContent>
        </Tabs>
      </div>

      <AcceptedRisksSheet
        open={risksOpen}
        onOpenChange={setRisksOpen}
        // The server re-syncs after an import; refresh once it has had time.
        onChanged={() => setTimeout(() => void load(), 4000)}
      />
    </div>
  );
}
