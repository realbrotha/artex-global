"use client";

import * as React from "react";

import {
  BuildingIcon,
  GlobeIcon,
  KeyRoundIcon,
  LayoutTemplateIcon,
  LinkIcon,
  type LucideIcon,
  NetworkIcon,
  RefreshCwIcon,
  SmartphoneIcon,
  Trash2Icon,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { AssetDslSearch } from "@/components/asset-dsl-search";
import { DrawerFooter, ListEmpty, PageHeader, TableSkeletonRows, useConfirm } from "@/components/page";
import { ScopeTextEditor } from "@/components/scope-text-editor";
import { PAGE_SIZE, TablePagination } from "@/components/table-pagination";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { parseCompanyScopeText } from "@/lib/company-scope";
import type { Asset, Company, CompanyScopeRule } from "@/lib/types";
import { cn } from "@/lib/utils";

const METHOD_COLOR: Record<string, string> = {
  GET: "bg-success/10 text-success",
  POST: "bg-info/10 text-info",
  PUT: "bg-warning/10 text-warning",
  PATCH: "bg-caution/10 text-caution",
  DELETE: "bg-danger/10 text-danger",
  HEAD: "bg-primary/10 text-primary",
  OPTIONS: "bg-muted text-muted-foreground",
};

function MethodBadge({ method }: { method: string }) {
  const m = method.toUpperCase();
  return (
    <span
      className={cn(
        "inline-block rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold leading-none",
        METHOD_COLOR[m] ?? "bg-muted text-muted-foreground",
      )}
    >
      {m || "—"}
    </span>
  );
}

function statusTone(code: number) {
  if (code >= 500) return "text-danger";
  if (code >= 400) return "text-warning";
  if (code >= 300) return "text-info";
  if (code >= 200) return "text-success";
  return "text-muted-foreground";
}

const TABS: { key: string; labelKey: string; icon: LucideIcon }[] = [
  { key: "company", labelKey: "company", icon: BuildingIcon },
  { key: "root_domain", labelKey: "rootDomain", icon: GlobeIcon },
  { key: "ip", labelKey: "ip", icon: NetworkIcon },
  { key: "subdomain", labelKey: "subdomain", icon: GlobeIcon },
  { key: "app", labelKey: "app", icon: SmartphoneIcon },
  { key: "service", labelKey: "service", icon: LayoutTemplateIcon },
  { key: "endpoint", labelKey: "endpoint", icon: LinkIcon },
];

export default function AssetsPage() {
  const t = useTranslations("assets");
  const confirm = useConfirm();
  const [rows, setRows] = React.useState<Asset[]>([]);
  const [total, setTotal] = React.useState(0);
  const [companies, setCompanies] = React.useState<Company[]>([]);
  const [companiesLoaded, setCompaniesLoaded] = React.useState(false);
  const [counts, setCounts] = React.useState<Record<string, number>>({});
  const [tab, setTab] = React.useState("company");
  const [query, setQuery] = React.useState("");
  const [loaded, setLoaded] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [page, setPage] = React.useState(0);
  const size = PAGE_SIZE;
  const [dslError, setDslError] = React.useState("");
  const [refreshKey, setRefreshKey] = React.useState(0);
  const assetsRequestRef = React.useRef(0);
  const [rowsTab, setRowsTab] = React.useState("");

  // asset selection & delete
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [deleting, setDeleting] = React.useState(false);

  // company delete
  const [companyDeleteTarget, setCompanyDeleteTarget] = React.useState<Company | null>(null);
  const [companyDeleteAssets, setCompanyDeleteAssets] = React.useState(false);
  const [companyDeleting, setCompanyDeleting] = React.useState(false);

  // Companies + per-type counts (tab badges) — loaded on demand, no background polling.
  const loadMeta = React.useCallback(() => {
    api
      .companies()
      .then(setCompanies)
      .catch(() => {
        /* Keep the last successful company snapshot on a transient failure. */
      })
      .finally(() => setCompaniesLoaded(true));
    api
      .assetCounts()
      .then(setCounts)
      .catch(() => {
        /* Keep the last successful counters on a transient failure. */
      });
  }, []);

  // Manual refresh: reload counts/companies and re-fetch the current page.
  const refresh = React.useCallback(() => {
    loadMeta();
    setRefreshKey((k) => k + 1);
    setSelected(new Set());
  }, [loadMeta]);

  const toggleSelect = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = (ids: number[]) => {
    setSelected((prev) => {
      const allSelected = ids.every((id) => prev.has(id));
      const next = new Set(prev);
      if (allSelected) {
        ids.forEach((id) => {
          next.delete(id);
        });
      } else {
        ids.forEach((id) => {
          next.add(id);
        });
      }
      return next;
    });
  };

  const openDelete = async (deleteIds: number[]) => {
    const ok = await confirm({
      title: t("deleteDialog.title"),
      description: t.rich("deleteDialog.body", {
        count: deleteIds.length,
        n: (chunks) => <span className="font-semibold tabular-nums">{chunks}</span>,
      }),
      confirmLabel: t("deleteDialog.confirm"),
      destructive: true,
    });
    if (!ok) return;
    setDeleting(true);
    try {
      const res = await api.deleteAssets(deleteIds);
      toast.success(t("toast.deleted", { count: res.deleted }));
      setSelected(new Set());
      refresh();
    } catch (e) {
      toast.error(t("toast.deleteFailed", { msg: String((e as Error)?.message ?? e) }));
    } finally {
      setDeleting(false);
    }
  };

  const confirmDeleteCompany = async () => {
    if (!companyDeleteTarget) return;
    setCompanyDeleting(true);
    try {
      const res = await api.deleteCompany(companyDeleteTarget.id, companyDeleteAssets);
      const msg =
        companyDeleteAssets && res.assets_deleted > 0
          ? t("toast.companyDeletedWithAssets", { count: res.assets_deleted })
          : t("toast.companyDeleted");
      toast.success(msg);
      refresh();
    } catch (e) {
      toast.error(t("toast.deleteFailed", { msg: String((e as Error)?.message ?? e) }));
    } finally {
      setCompanyDeleting(false);
      setCompanyDeleteTarget(null);
      setCompanyDeleteAssets(false);
    }
  };

  React.useEffect(() => {
    loadMeta();
  }, [loadMeta]);

  // Reset query + page + selection when switching tabs
  // biome-ignore lint/correctness/useExhaustiveDependencies: tab changes intentionally reset tab-local controls.
  React.useEffect(() => {
    setQuery("");
    setDslError("");
    setSelected(new Set());
    setRows([]);
    setRowsTab("");
    setTotal(0);
    setLoaded(false);
  }, [tab]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: these controls intentionally reset server pagination.
  React.useEffect(() => setPage(0), [tab, query]);

  const dslMode = query.trim() !== "";

  // Server-side paginated page loader for the active data tab (company tab excluded).
  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey is an explicit manual-reload trigger.
  React.useEffect(() => {
    if (tab === "company") return;
    const request = ++assetsRequestRef.current;
    const dsl = query.trim();
    setLoading(true);
    const offset = page * size;
    const run = async () => {
      try {
        const r = dsl ? await api.searchAssets(dsl, tab, size, offset) : await api.assets(tab, size, offset);
        if (assetsRequestRef.current !== request) return;
        setRows(r.assets);
        setRowsTab(tab);
        setTotal(r.total);
        setDslError("");
      } catch (e) {
        if (assetsRequestRef.current !== request) return;
        setDslError(String((e as Error)?.message ?? e));
        setRows([]);
        setRowsTab(tab);
        setTotal(0);
      } finally {
        if (assetsRequestRef.current === request) {
          setLoading(false);
          setLoaded(true);
        }
      }
    };
    const tid = setTimeout(run, dsl ? 400 : 0);
    return () => {
      clearTimeout(tid);
      if (assetsRequestRef.current === request) assetsRequestRef.current++;
    };
  }, [tab, page, size, query, refreshKey]);

  React.useEffect(() => {
    if (tab === "company") return;
    const lastPage = Math.max(0, Math.ceil(total / size) - 1);
    if (page > lastPage) setPage(lastPage);
  }, [page, tab, total]);

  const companyById = React.useMemo(() => {
    const m = new Map<number, string>();
    for (const c of companies) m.set(c.id, c.name);
    return m;
  }, [companies]);

  const companyName = (id?: number) => (id ? (companyById.get(id) ?? "") : "");

  const tabCounts: Record<string, number> = { ...counts, company: companies.length };
  const totalAssets = Object.values(counts).reduce((a, b) => a + b, 0);

  // rows are already the current server-side page.
  const tabData = (type: string): Asset[] => (rowsTab === type ? rows : []);
  const currentRows = tabData(tab);
  const slice = <T,>(list: T[]) => list;

  const searchBox = (
    <AssetDslSearch
      query={query}
      onChange={setQuery}
      loading={loading}
      error={dslError}
      count={dslMode ? total : undefined}
    />
  );

  return (
    <div data-page-fill className="flex min-h-0 flex-1 flex-col gap-4">
      <PageHeader actions={<CompanyDialog onSaved={refresh} />} />
      <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col">
        <div className="flex flex-wrap items-center gap-2">
          <div className="min-w-0 overflow-x-auto overflow-y-hidden">
            <TabsList variant="default">
              {TABS.map((tt) => (
                <TabsTrigger key={tt.key} value={tt.key}>
                  <tt.icon className="size-3.5" />
                  {t(`tab.${tt.labelKey}`)}
                  <span className="ml-1 tabular-nums text-muted-foreground">{tabCounts[tt.key]}</span>
                </TabsTrigger>
              ))}
            </TabsList>
          </div>
          <span className="ml-auto flex items-center gap-2">
            <span className="text-xs text-muted-foreground">
              {t.rich("totalAssets", {
                count: totalAssets,
                n: (chunks) => <span className="tabular-nums">{chunks}</span>,
              })}
            </span>
            {selected.size > 0 && (
              <Button
                variant="destructive"
                disabled={deleting}
                onClick={() => void openDelete(Array.from(selected) as number[])}
              >
                <Trash2Icon /> {t("deleteSelected", { count: selected.size })}
              </Button>
            )}
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={refresh}
              disabled={loading}
              aria-label={t("refresh")}
              title={t("refresh")}
            >
              <RefreshCwIcon className={cn(loading && "animate-spin")} />
            </Button>
          </span>
        </div>

        {/* 기업 */}
        <TabsContent value="company" className="flex min-h-0 flex-1 flex-col">
          {companiesLoaded && companies.length === 0 ? (
            <ListEmpty title={t("companyEmpty")} icon={<BuildingIcon />} />
          ) : (
            <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
              <div className="min-h-0 flex-1 overflow-auto">
                <Table>
                  <TableHeader className="sticky top-0 z-10 bg-card">
                    <TableRow>
                      <TableHead>{t("companyTable.name")}</TableHead>
                      <TableHead className="w-24 text-right">{t("companyTable.count")}</TableHead>
                      <TableHead>{t("companyTable.scope")}</TableHead>
                      <TableHead className="w-36 text-right">{t("companyTable.actions")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {companies.map((c) => (
                      <TableRow key={c.id}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <CompanyAvatar name={c.name} logo={c.logo} />
                            <span className="font-medium">{c.name}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-right tabular-nums text-sm">{c.asset_count}</TableCell>
                        <TableCell>
                          {c.scope?.length ? (
                            <div className="flex flex-wrap gap-1">
                              {c.scope.map((s, i) => (
                                <Badge key={i} variant="secondary" className="font-mono text-[11px]">
                                  {s.raw}
                                </Badge>
                              ))}
                            </div>
                          ) : (
                            <span className="text-xs text-muted-foreground">{t("noScope")}</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <EditScopeDialog company={c} onSaved={refresh} />
                            <AppendScopeDialog company={c} onSaved={refresh} />
                            <Button
                              variant="ghost"
                              size="icon-xs"
                              className="text-muted-foreground hover:text-danger"
                              onClick={() => {
                                setCompanyDeleteTarget(c);
                                setCompanyDeleteAssets(false);
                              }}
                              aria-label={t("deleteCompanyAria", { name: c.name })}
                            >
                              <Trash2Icon className="size-3.5" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {!companiesLoaded && <TableSkeletonRows columns={4} />}
                  </TableBody>
                </Table>
              </div>
            </Card>
          )}
        </TabsContent>

        {/* 루트 도메인 */}
        <TabsContent value="root_domain" className="flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", t("col.domain"), t("col.icp"), t("col.ownerCompany"), ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("root_domain")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="font-mono text-xs font-medium">{a.domain}</TableCell>
                <TableCell className="text-xs">{a.icp || "—"}</TableCell>
                <TableCell className="text-xs">
                  {companyName(a.company_id) || <span className="text-muted-foreground">{t("unassigned")}</span>}
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    className="text-muted-foreground hover:text-danger"
                    disabled={deleting}
                    onClick={() => void openDelete([a.id])}
                    aria-label={t("deleteAssetAria", { target: a.domain || a.id })}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* IP */}
        <TabsContent value="ip" className="flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", "IP", t("col.cSegment"), t("col.boundDomains"), t("col.openPorts"), ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("ip")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="font-mono text-xs font-medium">{a.ip}</TableCell>
                <TableCell className="font-mono text-xs">{a.c_segment || "—"}</TableCell>
                <TableCell>
                  <Chips items={a.bound_domains ?? []} mono />
                </TableCell>
                <TableCell>
                  <Chips
                    items={(a.open_ports ?? []).map((p) => (p.service ? `${p.port}/${p.service}` : String(p.port)))}
                    mono
                  />
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    className="text-muted-foreground hover:text-danger"
                    disabled={deleting}
                    onClick={() => void openDelete([a.id])}
                    aria-label={t("deleteAssetAria", { target: a.ip || a.id })}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 서브도메인 */}
        <TabsContent value="subdomain" className="flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", t("col.domain"), t("col.rootDomain"), t("col.recordType"), t("col.recordValue"), ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("subdomain")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="font-mono text-xs font-medium">{a.domain}</TableCell>
                <TableCell className="font-mono text-xs">{a.root_domain || "—"}</TableCell>
                <TableCell className="text-xs">{a.record_type || "—"}</TableCell>
                <TableCell className="max-w-xs truncate font-mono text-xs">
                  {(Array.isArray(a.record_value) ? a.record_value.join(", ") : a.record_value) || "—"}
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    className="text-muted-foreground hover:text-danger"
                    disabled={deleting}
                    onClick={() => void openDelete([a.id])}
                    aria-label={t("deleteAssetAria", { target: a.domain || a.id })}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 애플리케이션 */}
        <TabsContent value="app" className="flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", t("col.appName"), "Bundle ID", t("col.category"), t("col.icp"), ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("app")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="text-xs font-medium">{a.app_name || "—"}</TableCell>
                <TableCell className="font-mono text-xs">{a.bundle_id || "—"}</TableCell>
                <TableCell className="text-xs">{a.category || "—"}</TableCell>
                <TableCell className="text-xs">{a.app_icp || "—"}</TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    className="text-muted-foreground hover:text-danger"
                    disabled={deleting}
                    onClick={() => void openDelete([a.id])}
                    aria-label={t("deleteAssetAria", { target: a.app_name || a.id })}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>

        {/* 서비스 */}
        <TabsContent value="service" className="flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={[
              "",
              t("col.service"),
              t("col.domain"),
              "IP",
              t("col.port"),
              t("col.statusCode"),
              t("col.pageTitle"),
              t("col.fingerprint"),
              t("col.auth"),
              "",
            ]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("service")).map((a) => {
              const isHttp = a.service_type === "http";
              const svc = a.service_name || (isHttp ? "http" : "") || a.service_type || "";
              let domainCell: React.ReactNode = "—";
              if (isHttp && a.url) {
                domainCell = (
                  <a href={a.url} target="_blank" rel="noreferrer" className="text-info hover:underline">
                    {a.domain || a.url}
                  </a>
                );
              } else if (a.domain) {
                domainCell = a.domain;
              }
              return (
                <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                  <TableCell className="w-8 pr-0">
                    <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                  </TableCell>
                  <TableCell className="text-xs">
                    <Badge variant={isHttp ? "default" : "secondary"} className="font-mono text-[10px]">
                      {svc || "—"}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[14rem] truncate font-mono text-xs" title={a.domain || a.url}>
                    {domainCell}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{a.ip || "—"}</TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">{a.port || "—"}</TableCell>
                  <TableCell>
                    {a.status_code != null ? (
                      <span className={cn("font-mono text-xs font-semibold tabular-nums", statusTone(a.status_code))}>
                        {a.status_code}
                      </span>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  <TableCell className="max-w-[12rem] truncate text-xs" title={a.page_title}>
                    {a.page_title || "—"}
                  </TableCell>
                  <TableCell>
                    <Chips items={a.technologies ?? []} />
                  </TableCell>
                  <TableCell>
                    {(a.auth ?? []).length === 0 ? (
                      <span className="text-xs text-muted-foreground">—</span>
                    ) : (
                      (a.auth ?? []).map((authItem, i) => {
                        const item = authItem as Record<string, string>;
                        const label = item.type || item.username || t("authFallback");
                        return (
                          <span key={i} className="inline-flex items-center gap-1 text-[11px]">
                            <KeyRoundIcon className="size-3 text-muted-foreground" />
                            <span className="font-mono">{label}</span>
                          </span>
                        );
                      })
                    )}
                  </TableCell>
                  <TableCell className="w-8 pl-0">
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      className="text-muted-foreground hover:text-danger"
                      disabled={deleting}
                      onClick={() => void openDelete([a.id])}
                      aria-label={t("deleteAssetAria", { target: a.url || a.id })}
                    >
                      <Trash2Icon className="size-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              );
            })}
          </AssetCard>
        </TabsContent>

        {/* 엔드포인트 */}
        <TabsContent value="endpoint" className="flex min-h-0 flex-1 flex-col gap-2">
          {searchBox}
          <AssetCard
            cols={["", t("col.method"), t("col.fullUrl"), t("col.params"), ""]}
            loaded={loaded}
            total={total}
            page={page}
            size={size}
            onPage={setPage}
            rows={currentRows}
            selected={selected}
            onToggleAll={(ids) => toggleSelectAll(ids)}
          >
            {slice(tabData("endpoint")).map((a) => (
              <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                <TableCell className="w-8 pr-0">
                  <Checkbox checked={selected.has(a.id)} onCheckedChange={() => toggleSelect(a.id)} />
                </TableCell>
                <TableCell className="w-16">
                  <MethodBadge method={a.method || ""} />
                </TableCell>
                <TableCell className="max-w-sm truncate font-mono text-xs" title={a.url}>
                  {a.url || "—"}
                </TableCell>
                <TableCell>
                  <Chips
                    items={(a.params ?? []).map((p) => {
                      const item = p as Record<string, string>;
                      return item.name ? `${item.name}(${item.location || "?"})` : "?";
                    })}
                    mono
                  />
                </TableCell>
                <TableCell className="w-8 pl-0">
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    className="text-muted-foreground hover:text-danger"
                    disabled={deleting}
                    onClick={() => void openDelete([a.id])}
                    aria-label={t("deleteAssetAria", { target: a.url || a.id })}
                  >
                    <Trash2Icon className="size-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </AssetCard>
        </TabsContent>
      </Tabs>

      <AlertDialog
        open={!!companyDeleteTarget}
        onOpenChange={(o) => {
          if (!o) {
            setCompanyDeleteTarget(null);
            setCompanyDeleteAssets(false);
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("deleteCompanyDialog.title", { name: companyDeleteTarget?.name ?? "" })}
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-3">
                <p>{t("deleteCompanyDialog.body")}</p>
                <label
                  htmlFor="delete-assets-opt"
                  className="flex cursor-pointer items-center gap-2.5 rounded-md border p-3 hover:bg-muted/50"
                >
                  <Checkbox
                    id="delete-assets-opt"
                    checked={companyDeleteAssets}
                    onCheckedChange={(v) => setCompanyDeleteAssets(!!v)}
                  />
                  <span className="text-sm leading-snug">
                    {t("deleteCompanyDialog.alsoDeleteAssets")}
                    <span className="block text-xs text-muted-foreground">
                      {t("deleteCompanyDialog.alsoDeleteHint")}
                    </span>
                  </span>
                </label>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={companyDeleting}>{t("cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                void confirmDeleteCompany();
              }}
              disabled={companyDeleting}
              variant="destructive"
            >
              {companyDeleting ? t("deleting") : t("deleteDialog.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function AssetCard({
  cols,
  loaded,
  total,
  page,
  size,
  onPage,
  rows: dataRows,
  selected,
  onToggleAll,
  children,
}: {
  cols: string[];
  loaded: boolean;
  total: number;
  page: number;
  size: number;
  onPage: React.Dispatch<React.SetStateAction<number>>;
  rows?: Asset[];
  selected?: Set<number>;
  onToggleAll?: (ids: number[]) => void;
  children: React.ReactNode;
}) {
  const t = useTranslations("assets");
  const childRows = React.Children.toArray(children);

  const pageIds = dataRows?.map((r) => r.id) ?? [];
  const allSelected = pageIds.length > 0 && selected != null && pageIds.every((id) => selected.has(id));
  const someSelected = selected != null && pageIds.some((id) => selected.has(id));

  if (loaded && childRows.length === 0) return <ListEmpty title={t("emptyData")} />;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
        <div className="min-h-0 flex-1 overflow-auto scrollbar-thin scrollbar-track-transparent">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-card">
              <TableRow>
                {cols.map((c, i) =>
                  c === "" && i === 0 && onToggleAll ? (
                    <TableHead key={i} className="w-8 pr-0">
                      <Checkbox
                        checked={allSelected ? true : someSelected ? "indeterminate" : false}
                        onCheckedChange={() => onToggleAll(pageIds)}
                      />
                    </TableHead>
                  ) : (
                    <TableHead key={c + i}>{c}</TableHead>
                  ),
                )}
              </TableRow>
            </TableHeader>
            <TableBody>{childRows.length > 0 ? childRows : <TableSkeletonRows columns={cols.length} />}</TableBody>
          </Table>
        </div>
      </Card>
      {total > 0 && (
        <TablePagination page={page + 1} pageSize={size} total={total} onPageChange={(p) => onPage(p - 1)} />
      )}
    </div>
  );
}

function Chips({ items, mono }: { items: string[]; mono?: boolean }) {
  const clean = items.filter(Boolean);
  if (clean.length === 0) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {clean.map((s, i) => (
        <Badge key={i} variant="outline" className={cn("text-[10px]", mono && "font-mono")}>
          {s}
        </Badge>
      ))}
    </div>
  );
}

function CompanyAvatar({ name, logo }: { name: string; logo?: string }) {
  const initial = (name.trim()[0] ?? "?").toUpperCase();
  return (
    <Avatar className="size-7 shrink-0">
      {logo ? <AvatarImage src={logo} alt={name} /> : null}
      <AvatarFallback className="text-xs">{initial}</AvatarFallback>
    </Avatar>
  );
}

// 백엔드가 돌려주는 warnings 는 기존 데이터의 문제를 가리키며(이번에 제출한 행이 잘못된 것이 아니다), 저장 자체는 이미
// 성공한 상태다. 사용자가 구체적인 자산을 직접 처리해야 하므로, 제목만 훑어서는 부족해 더 긴 노출 시간을 준다.
function showScopeWarnings(warnings?: string[]) {
  for (const warning of warnings ?? []) {
    toast.warning(warning, { duration: 15000 });
  }
}

function savedScopeRules(company: Company): CompanyScopeRule[] {
  return (company.scope ?? [])
    .map((scope) => ({ kind: scope.kind, value: scope.raw.trim() }))
    .filter((scope) => scope.value);
}

function savedScopeText(company: Company): string {
  return savedScopeRules(company)
    .map((scope) => scope.value)
    .join("\n");
}

// 기업 추가는 작업·LLM 편집과 같은 오른쪽 서랍(drawer)을 사용한다.
function CompanyDialog({ onSaved }: { onSaved: () => void }) {
  const t = useTranslations("assets");
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [scopeText, setScopeText] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const parsedScope = React.useMemo(() => parseCompanyScopeText(scopeText), [scopeText]);

  React.useEffect(() => {
    if (!open) return;
    setName("");
    setScopeText("");
  }, [open]);

  const submit = async () => {
    if (!name.trim()) {
      toast.error(t("companyDialog.nameRequired"));
      return;
    }
    if (parsedScope.errors.length > 0) {
      toast.error(t("fixInvalidScope"));
      return;
    }
    setBusy(true);
    try {
      const res = await api.createCompany(name.trim(), parsedScope.rules);
      const added = res.scope_added ?? 0;
      const invalid = res.scope_invalid ?? 0;
      if (invalid > 0) toast.warning(t("companyDialog.createdWithInvalid", { added, invalid }));
      else toast.success(t("companyDialog.created", { added }));
      setOpen(false);
      onSaved();
    } catch (e) {
      const msg = String((e as Error)?.message ?? e);
      if (/:\s*409$/.test(msg)) toast.error(t("companyDialog.exists"));
      else toast.error(t("saveFailed", { msg }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button>
          <BuildingIcon data-icon="inline-start" /> {t("companyDialog.addButton")}
        </Button>
      </SheetTrigger>
      <SheetContent size="md" className="gap-0">
        <SheetHeader className="border-b">
          <SheetTitle>{t("companyDialog.title")}</SheetTitle>
          <SheetDescription>{t("companyDialog.description")}</SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="cn-name">{t("companyDialog.nameLabel")}</FieldLabel>
              <Input
                id="cn-name"
                placeholder={t("companyDialog.namePlaceholder")}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <ScopeTextEditor id="cn-scope" value={scopeText} onValueChange={setScopeText} parsed={parsedScope} />
          </FieldGroup>
        </div>
        <DrawerFooter
          onCancel={() => setOpen(false)}
          onConfirm={() => void submit()}
          confirmDisabled={!name.trim() || parsedScope.errors.length > 0}
          pending={busy}
          confirmLabel={busy ? t("saving") : t("save")}
        />
      </SheetContent>
    </Sheet>
  );
}

// 자산 범위 편집(덮어쓰기) 팝업
function EditScopeDialog({ company, onSaved }: { company: Company; onSaved: () => void }) {
  const t = useTranslations("assets");
  const [open, setOpen] = React.useState(false);
  const [scopeText, setScopeText] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const preservedScopeRules = React.useMemo(() => savedScopeRules(company), [company]);
  const parsedScope = React.useMemo(
    () => parseCompanyScopeText(scopeText, { preservedRules: preservedScopeRules }),
    [preservedScopeRules, scopeText],
  );

  React.useEffect(() => {
    if (!open) return;
    setScopeText(savedScopeText(company));
    setReason("");
  }, [open, company]);

  const submit = async () => {
    if (parsedScope.errors.length > 0) {
      toast.error(t("fixInvalidScope"));
      return;
    }
    setBusy(true);
    try {
      const res = await api.updateCompanyScope(company.id, parsedScope.rules, reason);
      const errCount = res.invalid ?? 0;
      if (errCount > 0) toast.warning(t("editScope.savedWithInvalid", { invalid: errCount }));
      else toast.success(t("editScope.updated", { added: res.added }));
      showScopeWarnings(res.warnings);
      setOpen(false);
      onSaved();
    } catch (e) {
      toast.error(t("saveFailed", { msg: String((e as Error)?.message ?? e) }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="outline" size="xs">
          {t("editScope.button")}
        </Button>
      </SheetTrigger>
      <SheetContent size="md" className="gap-0">
        <SheetHeader className="border-b">
          <SheetTitle>{t("editScope.title", { name: company.name })}</SheetTitle>
          <SheetDescription>{t("editScope.description")}</SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
          <FieldGroup>
            <ScopeTextEditor
              id={`edit-company-scope-${company.id}`}
              value={scopeText}
              onValueChange={setScopeText}
              parsed={parsedScope}
            />
            <Field>
              <FieldLabel htmlFor="es-reason">{t("reasonLabel")}</FieldLabel>
              <Input
                id="es-reason"
                placeholder={t("reasonPlaceholder")}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </Field>
          </FieldGroup>
        </div>
        <DrawerFooter
          onCancel={() => setOpen(false)}
          onConfirm={() => void submit()}
          confirmDisabled={parsedScope.errors.length > 0}
          pending={busy}
          confirmLabel={busy ? t("saving") : t("editScope.overwrite")}
        />
      </SheetContent>
    </Sheet>
  );
}

// 자산 범위 추가 팝업
function AppendScopeDialog({ company, onSaved }: { company: Company; onSaved: () => void }) {
  const t = useTranslations("assets");
  const [open, setOpen] = React.useState(false);
  const [scopeText, setScopeText] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const parsedScope = React.useMemo(() => parseCompanyScopeText(scopeText), [scopeText]);

  React.useEffect(() => {
    if (!open) return;
    setScopeText("");
    setReason("");
  }, [open]);

  const submit = async () => {
    if (parsedScope.rules.length === 0) {
      toast.error(t("appendScope.scopeRequired"));
      return;
    }
    if (parsedScope.errors.length > 0) {
      toast.error(t("fixInvalidScope"));
      return;
    }
    setBusy(true);
    try {
      const res = await api.addCompanyScope(company.id, parsedScope.rules, reason);
      const errCount = res.invalid ?? 0;
      if (errCount > 0) toast.warning(t("editScope.savedWithInvalid", { invalid: errCount }));
      else toast.success(t("appendScope.appended", { added: res.added }));
      showScopeWarnings(res.warnings);
      setOpen(false);
      onSaved();
    } catch (e) {
      toast.error(t("saveFailed", { msg: String((e as Error)?.message ?? e) }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="outline" size="xs">
          {t("appendScope.button")}
        </Button>
      </SheetTrigger>
      <SheetContent size="md" className="gap-0">
        <SheetHeader className="border-b">
          <SheetTitle>{t("appendScope.title", { name: company.name })}</SheetTitle>
          <SheetDescription>{t("appendScope.description")}</SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
          <FieldGroup>
            <ScopeTextEditor
              id={`append-company-scope-${company.id}`}
              value={scopeText}
              onValueChange={setScopeText}
              parsed={parsedScope}
            />
            <Field>
              <FieldLabel htmlFor="as-reason">{t("reasonLabel")}</FieldLabel>
              <Input
                id="as-reason"
                placeholder={t("reasonPlaceholder")}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </Field>
          </FieldGroup>
        </div>
        <DrawerFooter
          onCancel={() => setOpen(false)}
          onConfirm={() => void submit()}
          confirmDisabled={parsedScope.rules.length === 0 || parsedScope.errors.length > 0}
          pending={busy}
          confirmLabel={busy ? t("saving") : t("appendScope.button")}
        />
      </SheetContent>
    </Sheet>
  );
}
