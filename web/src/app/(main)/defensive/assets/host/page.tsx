"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowLeftIcon, RefreshCwIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import {
  type AssetEdge,
  type AssetNode,
  assetStatusGroup,
  caseInvolvesHost,
  hostDetailUrl,
  isHostNode,
  wazuhApi,
} from "@/lib/wazuh-api";

import { CaseList, isCleared, type ListedCase } from "../_components/case-list";
import { CheckTiles, HostChecks } from "../_components/host-checks";

const ASSETS_URL = "/defensive/assets";
const TABS = ["overview", "checks", "cases"] as const;
type Tab = (typeof TABS)[number];

const statusText: Record<string, string> = {
  ok: "text-emerald-600 dark:text-emerald-400",
  down: "text-red-600 dark:text-red-400",
  missing: "text-amber-600 dark:text-amber-400",
};

interface Loaded {
  sourceName: string;
  node: AssetNode | null;
  nodes: AssetNode[];
  edges: AssetEdge[];
  cases: ListedCase[];
}

// One host at full width: what it is, its config-check results and the case
// candidates that name it. The host is addressed by ?source=&node= so other
// screens can link to it.
export default function HostDetailPage() {
  const t = useTranslations("protectedAssets");
  const [target, setTarget] = React.useState<{ source: string; node: string } | null>(null);
  const [tab, setTab] = React.useState<Tab>("overview");
  const [data, setData] = React.useState<Loaded | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setTarget({ source: params.get("source") ?? "", node: params.get("node") ?? "" });
    const wanted = params.get("tab");
    if (TABS.includes(wanted as Tab)) setTab(wanted as Tab);
  }, []);

  const load = React.useCallback(async () => {
    if (!target) return;
    setLoading(true);
    try {
      const [a, k] = await Promise.all([wazuhApi.assets(), wazuhApi.cases()]);
      const source = a.sources.find((s) => s.id === target.source);
      const cases = (k.sources.find((s) => s.id === target.source)?.cases ?? [])
        .filter((c) => caseInvolvesHost(c, target.node))
        .map((c) => ({ ...c, sourceId: target.source, sourceName: source?.name ?? "" }));
      setData({
        sourceName: source?.name ?? "",
        node: source?.nodes.find((n) => n.id === target.node) ?? null,
        nodes: source?.nodes ?? [],
        edges: source?.edges ?? [],
        cases,
      });
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [target, t]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const node = data?.node ?? null;
  const liveCases = React.useMemo(() => (data?.cases ?? []).filter((c) => !isCleared(c)), [data]);
  const clearedCount = (data?.cases.length ?? 0) - liveCases.length;
  const [showCleared, setShowCleared] = React.useState(false);
  const group = node ? assetStatusGroup(node) : "none";
  const checks = node?.checks;
  const issueCount = checks ? checks.fail + checks.review + checks.error : 0;

  const relations = React.useMemo(() => {
    if (!data || !node) return [];
    const byId = new Map(data.nodes.map((n) => [n.id, n]));
    return data.edges
      .filter((e) => e.from === node.id || e.to === node.id)
      .map((e) => {
        const other = byId.get(e.from === node.id ? e.to : e.from);
        return {
          key: `${e.kind}:${e.from}>${e.to}`,
          label: t(e.from === node.id ? `relation.${e.kind}` : `relation.${e.kind}_reverse`),
          other,
        };
      })
      .filter((r) => r.other);
  }, [data, node, t]);

  const selectTab = (value: string) => {
    setTab(value as Tab);
    const params = new URLSearchParams(window.location.search);
    if (value === "overview") params.delete("tab");
    else params.set("tab", value);
    window.history.replaceState(null, "", `?${params.toString()}`);
  };

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <Button asChild variant="ghost" size="sm" className="-ml-2">
          <Link href={ASSETS_URL}>
            <ArrowLeftIcon />
            {t("title")}
          </Link>
        </Button>
        {node && (
          <>
            <h1 className="font-semibold">{node.name}</h1>
            <span className="text-muted-foreground text-sm">
              {[t(`kind.${node.kind}`), node.ip].filter(Boolean).join(" · ")}
            </span>
            {group !== "none" && <span className={cn("text-sm", statusText[group])}>{t(`status.${group}`)}</span>}
          </>
        )}
        <Button variant="outline" size="sm" className="ml-auto" onClick={() => void load()} disabled={loading}>
          <RefreshCwIcon className={cn(loading && "animate-spin")} />
          {t("refresh")}
        </Button>
      </div>

      <div className="flex flex-1 flex-col gap-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {data === null && !error && <Skeleton className="h-96 w-full" />}
        {data !== null && (!node || !isHostNode(node)) && (
          <p className="rounded-lg border border-dashed p-10 text-center text-muted-foreground text-sm">
            {t("host.notFound")}
          </p>
        )}
        {node && isHostNode(node) && target && (
          <Tabs value={tab} onValueChange={selectTab} className="flex flex-1 flex-col">
            <TabsList>
              <TabsTrigger value="overview">{t("host.tabOverview")}</TabsTrigger>
              <TabsTrigger value="checks">
                {t("checks.title")}
                {issueCount > 0 && <span className="ml-1 text-[10px] tabular-nums">{issueCount}</span>}
              </TabsTrigger>
              <TabsTrigger value="cases">
                {t("cases.tab")}
                {liveCases.length > 0 && (
                  <span className="ml-1 rounded-full bg-red-500/15 px-1.5 text-[10px] text-red-700 tabular-nums dark:text-red-300">
                    {liveCases.length}
                  </span>
                )}
              </TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <section className="grid grid-cols-1 content-start gap-3 rounded-lg border p-4 text-sm">
                <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
                  {(
                    [
                      ["status", group === "none" ? "" : t(`status.${group}`)],
                      ["publicIp", node.public_ip],
                      ["ip", node.ip],
                      ["os", node.os],
                      ["virt", node.virt],
                      ["lastSeen", node.last_seen ? new Date(node.last_seen).toLocaleString() : ""],
                      ["checked", node.checked],
                      ["connection", data?.sourceName],
                    ] as const
                  )
                    .filter(([, value]) => value)
                    .map(([key, value]) => (
                      <div key={key} className="min-w-0">
                        <dt className="text-[11px] text-muted-foreground">{t(`field.${key}`)}</dt>
                        <dd className="break-words">{value}</dd>
                      </div>
                    ))}
                </dl>
                {(
                  [
                    ["roles", node.roles],
                    ["services", node.services],
                    ["groups", node.groups],
                  ] as const
                )
                  .filter(([, list]) => list?.length)
                  .map(([key, list]) => (
                    <div key={key}>
                      <p className="text-[11px] text-muted-foreground">{t(`field.${key}`)}</p>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {list?.map((item) => (
                          <Badge key={item} variant="secondary">
                            {item}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                {(node.addrs?.length ?? 0) > 0 && (
                  <div>
                    <p className="text-[11px] text-muted-foreground">{t("field.addrs")}</p>
                    <ul className="mt-1 grid grid-cols-1 gap-x-6 gap-y-0.5 sm:grid-cols-2">
                      {node.addrs?.map((addr) => (
                        <li key={addr.ip} className="flex min-w-0 items-baseline gap-2">
                          <span className="break-all font-mono text-xs">{addr.ip}</span>
                          <span className="truncate text-[11px] text-muted-foreground">{addr.iface}</span>
                          {addr.public && <Badge variant="outline">{t("host.public")}</Badge>}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </section>

              <div className="grid grid-cols-1 content-start gap-4">
                <section className="grid grid-cols-1 gap-2 rounded-lg border p-4 text-sm">
                  <div className="flex items-center justify-between">
                    <h2 className="font-medium">{t("checks.title")}</h2>
                    {checks && (
                      <Button variant="ghost" size="sm" onClick={() => selectTab("checks")}>
                        {t("host.detail")}
                      </Button>
                    )}
                  </div>
                  {checks ? (
                    <CheckTiles checks={checks} />
                  ) : (
                    <p className="text-muted-foreground">{t("checks.none")}</p>
                  )}
                </section>
                <section className="grid grid-cols-1 gap-2 rounded-lg border p-4 text-sm">
                  <div className="flex items-center justify-between">
                    <h2 className="font-medium">{t("cases.hostTitle", { count: liveCases.length })}</h2>
                    {liveCases.length > 0 && (
                      <Button variant="ghost" size="sm" onClick={() => selectTab("cases")}>
                        {t("host.detail")}
                      </Button>
                    )}
                  </div>
                  {liveCases.length === 0 && <p className="text-muted-foreground">{t("cases.empty")}</p>}
                  <ul className="grid grid-cols-1 gap-1">
                    {liveCases.slice(0, 3).map((c) => (
                      <li key={c.id} className="truncate text-muted-foreground">
                        {t(`cases.severity.${c.severity}`)} · {c.verdict?.title ?? c.title ?? c.criterion}
                      </li>
                    ))}
                  </ul>
                </section>
                {relations.length > 0 && (
                  <section className="grid grid-cols-1 gap-2 rounded-lg border p-4 text-sm">
                    <h2 className="font-medium">{t("field.relations")}</h2>
                    <ul className="grid grid-cols-1 gap-1">
                      {relations.map((r) => (
                        <li key={r.key} className="truncate">
                          <span className="text-muted-foreground">{r.label}</span>{" "}
                          {r.other && isHostNode(r.other) ? (
                            <a className="underline underline-offset-2" href={hostDetailUrl(target.source, r.other.id)}>
                              {r.other.name}
                            </a>
                          ) : (
                            r.other?.name
                          )}
                        </li>
                      ))}
                    </ul>
                  </section>
                )}
              </div>
            </TabsContent>

            <TabsContent value="checks">
              {checks ? (
                <HostChecks sourceId={target.source} nodeId={target.node} checks={checks} />
              ) : (
                <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
                  {t("checks.none")}
                </p>
              )}
            </TabsContent>

            <TabsContent value="cases" className="grid grid-cols-1 content-start gap-3">
              {clearedCount > 0 && (
                <label className="flex items-center gap-1.5 text-muted-foreground text-xs">
                  <input type="checkbox" checked={showCleared} onChange={(e) => setShowCleared(e.target.checked)} />
                  {t("cases.showKnown", { count: clearedCount })}
                </label>
              )}
              {(showCleared ? (data?.cases ?? []) : liveCases).length === 0 ? (
                <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
                  {t("cases.empty")}
                </p>
              ) : (
                <CaseList cases={showCleared ? (data?.cases ?? []) : liveCases} onCorrected={() => void load()} />
              )}
            </TabsContent>
          </Tabs>
        )}
      </div>
    </div>
  );
}
