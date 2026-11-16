"use client";

import * as React from "react";

import { CableIcon, NetworkIcon, RefreshCwIcon, SearchIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import {
  type AssetEdge,
  type AssetNode,
  type AssetSource,
  assetStatusGroup,
  isHostNode,
  type WazuhSource,
  wazuhApi,
} from "@/lib/wazuh-api";

import { AssetGraph } from "./_components/asset-graph";
import { WazuhConnections } from "./_components/wazuh-connections";

type Filter = "all" | "ok" | "down" | "missing";
type MergedNode = AssetNode & { sourceName: string };

const statusText: Record<string, string> = {
  ok: "text-emerald-600 dark:text-emerald-400",
  down: "text-red-600 dark:text-red-400",
  missing: "text-amber-600 dark:text-amber-400",
};

// Node ids are only unique within one connection, so they are namespaced by
// connection before the graphs are drawn together.
function merge(sources: AssetSource[]): { nodes: MergedNode[]; edges: AssetEdge[] } {
  const nodes: MergedNode[] = [];
  const edges: AssetEdge[] = [];
  for (const source of sources) {
    const prefix = `${source.id}/`;
    for (const node of source.nodes) nodes.push({ ...node, id: prefix + node.id, sourceName: source.name });
    for (const edge of source.edges) edges.push({ ...edge, from: prefix + edge.from, to: prefix + edge.to });
  }
  return { nodes, edges };
}

export default function ProtectedAssetsPage() {
  const t = useTranslations("protectedAssets");
  const [assets, setAssets] = React.useState<AssetSource[] | null>(null);
  const [connections, setConnections] = React.useState<WazuhSource[]>([]);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [sheetOpen, setSheetOpen] = React.useState(false);
  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const [query, setQuery] = React.useState("");
  const [filter, setFilter] = React.useState<Filter>("all");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [a, c] = await Promise.all([wazuhApi.assets(), wazuhApi.sources()]);
      setAssets(a.sources);
      setConnections(c.sources);
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
  const hosts = React.useMemo(() => nodes.filter(isHostNode), [nodes]);

  const counts = React.useMemo(() => {
    const c = { all: hosts.length, ok: 0, down: 0, missing: 0 };
    for (const h of hosts) {
      const g = assetStatusGroup(h);
      if (g !== "none") c[g] += 1;
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
        .filter((h) => filter === "all" || assetStatusGroup(h) === filter)
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
        .sort((a, b) => a.name.localeCompare(b.name)),
    [hosts, visible],
  );

  const selected = React.useMemo(() => nodes.find((n) => n.id === selectedId) ?? null, [nodes, selectedId]);
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
  ];

  return (
    <div className="flex flex-1 flex-col">
      <header className="flex flex-wrap items-center gap-3 border-b px-4 py-3 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <NetworkIcon className="size-5 text-violet-500" />
        <h1 className="font-semibold">{t("title")}</h1>
        <div className="ml-auto flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={cn(loading && "animate-spin")} />
            {t("refresh")}
          </Button>
          <Button size="sm" onClick={() => setSheetOpen(true)}>
            <CableIcon />
            {t("manageConnections")}
          </Button>
        </div>
      </header>

      <div className="flex flex-1 flex-col gap-4 p-4 lg:p-6">
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

        {assets === null ? (
          <Skeleton className="h-96 w-full" />
        ) : assets.length === 0 ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 rounded-lg border border-dashed p-10 text-center">
            <NetworkIcon className="size-8 text-muted-foreground" />
            <p className="font-medium">{t("emptyTitle")}</p>
            <p className="max-w-md text-muted-foreground text-sm">{t("emptyDescription")}</p>
            <Button onClick={() => setSheetOpen(true)}>
              <CableIcon />
              {t("addConnection")}
            </Button>
          </div>
        ) : (
          <>
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

            <Tabs defaultValue="graph" className="flex flex-1 flex-col">
              <TabsList>
                <TabsTrigger value="graph">{t("tabGraph")}</TabsTrigger>
                <TabsTrigger value="list">{t("tabList")}</TabsTrigger>
              </TabsList>

              <TabsContent value="graph" className="flex flex-1 flex-col gap-2">
                <div className="flex min-h-[560px] flex-1 overflow-hidden rounded-lg border">
                  <div className="min-w-0 flex-1">
                    <AssetGraph
                      nodes={visible.nodes}
                      edges={visible.edges}
                      selectedId={selectedId}
                      onSelect={setSelectedId}
                    />
                  </div>
                  {selected && (
                    <aside className="w-72 shrink-0 overflow-y-auto border-l bg-card p-4 text-sm">
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
                      <dl className="mt-3 grid gap-2.5">
                        {(
                          [
                            ["status", statusLabel(selected)],
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
                <p className="text-muted-foreground text-xs">{t("legend")}</p>
              </TabsContent>

              <TabsContent value="list">
                <div className="overflow-x-auto rounded-lg border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        {(["name", "kind", "status", "roles", "services", "ip", "os"] as const).map((col) => (
                          <TableHead key={col}>{t(`column.${col}`)}</TableHead>
                        ))}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {listed.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                            {t("noMatch")}
                          </TableCell>
                        </TableRow>
                      )}
                      {listed.map((h) => (
                        <TableRow key={h.id}>
                          <TableCell className="font-medium">{h.name}</TableCell>
                          <TableCell>{t(`kind.${h.kind}`)}</TableCell>
                          <TableCell className={statusText[assetStatusGroup(h)]}>{statusLabel(h)}</TableCell>
                          <TableCell>{h.roles?.join(", ")}</TableCell>
                          <TableCell>{h.services?.join(", ")}</TableCell>
                          <TableCell className="font-mono text-xs">{h.ip}</TableCell>
                          <TableCell>{h.os}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>

      <WazuhConnections
        open={sheetOpen}
        onOpenChange={setSheetOpen}
        sources={connections}
        onChanged={() => void load()}
      />
    </div>
  );
}
