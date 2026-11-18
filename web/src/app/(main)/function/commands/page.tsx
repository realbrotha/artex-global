"use client";

import * as React from "react";

import { BarChart3Icon, Loader2Icon, SearchIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { ListEmpty, PageHeader, TableSkeletonRows } from "@/components/page";
import { PAGE_SIZE, TablePagination } from "@/components/table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getDateLocale } from "@/i18n/datetime";
import { api } from "@/lib/api";
import type { CommandRecord, ToolStat } from "@/lib/types";
import { cn } from "@/lib/utils";

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString(getDateLocale(), {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

// toolInput renders a tool's raw input for display. Bash's {"command":"..."} is
// unwrapped to the bare command; other tools show their pretty-printed JSON args.
function toolInput(raw: string): string {
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj.command === "string") return obj.command;
    return JSON.stringify(obj, null, 2);
  } catch {
    /* not JSON */
  }
  return raw;
}

// truncate clips a string to maxLen characters.
function truncate(s: string, maxLen: number): string {
  const first = s.split("\n")[0]; // single-line preview
  if (first.length <= maxLen) return first;
  return first.slice(0, maxLen) + "…";
}

const CMD_MAX_LEN = 80;

export default function CommandsPage() {
  const t = useTranslations("commands");
  const [page, setPage] = React.useState(0);
  const size = PAGE_SIZE;
  const [query, setQuery] = React.useState("");
  const [queryQ, setQueryQ] = React.useState("");
  const [taskFilter, setTaskFilter] = React.useState("");

  const [commands, setCommands] = React.useState<CommandRecord[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(true);

  // 도구별 호출 횟수. 팝업을 열 때만 가져온다(집계 질의가 한 번 더 들어가므로 페이지를 넘길 때마다 부담하지 않는다).
  const [statsOpen, setStatsOpen] = React.useState(false);
  const [stats, setStats] = React.useState<ToolStat[]>([]);
  const [statsLoading, setStatsLoading] = React.useState(false);

  // Selected execution is rendered in a right-side detail sheet.
  const [selected, setSelected] = React.useState<CommandRecord | null>(null);

  // Debounce search input.
  React.useEffect(() => {
    const t = setTimeout(() => setQueryQ(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  // Reset page on filter change.
  // biome-ignore lint/correctness/useExhaustiveDependencies: every filter change intentionally resets pagination.
  React.useEffect(() => {
    setPage(0);
  }, [queryQ, taskFilter]);

  // Load data.
  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .commands({ task: taskFilter || undefined, q: queryQ || undefined, page, size })
      .then((r) => {
        if (!alive) return;
        setCommands(r.commands ?? []);
        setTotal(r.total ?? 0);
      })
      .catch(() => {
        if (!alive) return;
        setCommands([]);
        setTotal(0);
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [page, queryQ, taskFilter]);

  // 통계는 필터 조건을 따라가며, 표가 보여 주는 것과 같은 기록 묶음을 대상으로 한다(단 페이지는 나누지 않는다).
  React.useEffect(() => {
    if (!statsOpen) return;
    let alive = true;
    setStatsLoading(true);
    api
      .commandStats({ task: taskFilter || undefined, q: queryQ || undefined })
      .then((r) => alive && setStats(r.stats ?? []))
      .catch(() => alive && setStats([]))
      .finally(() => alive && setStatsLoading(false));
    return () => {
      alive = false;
    };
  }, [statsOpen, queryQ, taskFilter]);

  const statsTotal = stats.reduce((n, s) => n + s.total, 0);
  const statsErrors = stats.reduce((n, s) => n + s.errors, 0);
  const statsMax = stats.reduce((n, s) => Math.max(n, s.total), 0);

  return (
    <div data-page-fill className="flex min-h-0 flex-1 flex-col gap-4">
      <PageHeader />
      {/* 도구 줄: 검색 · 작업 필터 · 끝에 통계 버튼. 건수는 표 아래 쪽 번호에 표시 */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-80">
          <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder={t("searchPlaceholder")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8"
          />
        </div>
        <Input
          placeholder={t("taskIdPlaceholder")}
          className="w-28"
          value={taskFilter}
          onChange={(e) => setTaskFilter(e.target.value.replace(/\D/g, ""))}
        />
        <Button variant="outline" className="ml-auto" onClick={() => setStatsOpen(true)}>
          <BarChart3Icon />
          {t("stats")}
        </Button>
      </div>

      {/* History table */}
      {!loading && commands.length === 0 ? (
        <ListEmpty title={t("empty")} />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col">
          <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
            <div className="min-h-0 flex-1 overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead className="w-[130px]">{t("colTime")}</TableHead>
                    <TableHead className="w-[60px]">{t("colTask")}</TableHead>
                    <TableHead className="w-[90px]">Worker</TableHead>
                    <TableHead className="w-[110px]">{t("colTool")}</TableHead>
                    <TableHead>{t("colInput")}</TableHead>
                    <TableHead className="w-[60px]">{t("colStatus")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading && commands.length === 0 ? (
                    <TableSkeletonRows columns={6} />
                  ) : (
                    commands.map((cmd) => (
                      <TableRow
                        key={cmd.id}
                        className={cn("cursor-pointer", selected?.id === cmd.id && "bg-accent hover:bg-accent")}
                        onClick={() => setSelected(cmd)}
                      >
                        <TableCell className="text-xs text-muted-foreground tabular-nums">
                          {fmtTime(cmd.created_at)}
                        </TableCell>
                        <TableCell className="text-xs font-mono text-muted-foreground">#{cmd.exploration_id}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs font-mono">
                            {cmd.worker || "-"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary" className="text-xs font-mono">
                            {cmd.tool || "-"}
                          </Badge>
                        </TableCell>
                        <TableCell className="max-w-0">
                          <code className="block truncate font-mono text-xs">
                            {truncate(toolInput(cmd.command), CMD_MAX_LEN)}
                          </code>
                        </TableCell>
                        <TableCell>
                          {cmd.is_error ? (
                            <Badge variant="destructive" className="text-xs">
                              {t("failed")}
                            </Badge>
                          ) : (
                            <Badge variant="secondary" className="text-xs text-success">
                              {t("success")}
                            </Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </Card>
          <TablePagination page={page + 1} total={total} onPageChange={(p) => setPage(p - 1)} />
        </div>
      )}

      {/* 도구 호출 통계: 표와 같은 기록 묶음(같은 필터, 페이지 나눔 없음) */}
      <Dialog open={statsOpen} onOpenChange={setStatsOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("statsTitle")}</DialogTitle>
            <DialogDescription>
              {taskFilter || queryQ ? t("statsDescFiltered") : t("statsDescAll")}
              {stats.length > 0 && (
                <>
                  {" · "}
                  <span className="tabular-nums">{stats.length}</span>
                  {t("unitTools")} · <span className="tabular-nums">{statsTotal}</span>
                  {t("unitCalls")}
                  {statsErrors > 0 && (
                    <>
                      {" · "}
                      {t("failed")} <span className="tabular-nums text-danger">{statsErrors}</span>
                    </>
                  )}
                </>
              )}
            </DialogDescription>
          </DialogHeader>

          {statsLoading && stats.length === 0 ? (
            <div className="py-10 text-center">
              <Loader2Icon className="mx-auto h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : stats.length === 0 ? (
            <div className="py-10 text-center text-sm text-muted-foreground">{t("statsEmpty")}</div>
          ) : (
            <div className="-mr-2 max-h-[55vh] space-y-1 overflow-auto pr-2">
              {stats.map((s) => (
                <div key={s.tool} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-md p-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-mono text-xs font-medium">{s.tool}</span>
                      {s.errors > 0 && (
                        <span className="text-[11px] tabular-nums text-danger">
                          {t("failed")} {s.errors}
                        </span>
                      )}
                    </div>
                    <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${statsMax > 0 ? (s.total / statsMax) * 100 : 0}%` }}
                      />
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs font-semibold tabular-nums">{s.total}</div>
                    <div className="text-[11px] tabular-nums text-muted-foreground">
                      {statsTotal > 0 ? ((s.total / statsTotal) * 100).toFixed(1) : "0.0"}%
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent size="md" className="gap-0">
          {selected && (
            <>
              <SheetHeader className="border-b">
                <SheetTitle className="pr-8">{t("detailTitle")}</SheetTitle>
                <SheetDescription>{fmtTime(selected.created_at)}</SheetDescription>
                <div className="flex flex-wrap items-center gap-2 pt-2">
                  <Badge variant="outline" className="text-xs font-mono">
                    #{selected.exploration_id}
                  </Badge>
                  <Badge variant="outline" className="text-xs font-mono">
                    {selected.worker || "-"}
                  </Badge>
                  <Badge variant="secondary" className="text-xs font-mono">
                    {selected.tool || "-"}
                  </Badge>
                  {selected.is_error ? (
                    <Badge variant="destructive" className="text-xs">
                      {t("failed")}
                    </Badge>
                  ) : (
                    <Badge variant="secondary" className="text-xs text-success">
                      {t("success")}
                    </Badge>
                  )}
                </div>
              </SheetHeader>
              <div className="grid min-h-0 flex-1 grid-rows-2 divide-y">
                <div className="flex min-h-0 min-w-0 flex-col">
                  <div className="border-b px-5 py-2 text-xs font-medium text-muted-foreground">{t("inputLabel")}</div>
                  <div className="min-h-0 flex-1 overflow-auto">
                    <pre className="p-5 font-mono text-xs break-all whitespace-pre-wrap">
                      {toolInput(selected.command)}
                    </pre>
                  </div>
                </div>
                <div className="flex min-h-0 min-w-0 flex-col">
                  <div className="border-b px-5 py-2 text-xs font-medium text-muted-foreground">{t("outputLabel")}</div>
                  <div className="min-h-0 flex-1 overflow-auto">
                    <pre
                      className={cn(
                        "p-5 font-mono text-xs break-all whitespace-pre-wrap",
                        selected.is_error && "text-danger",
                      )}
                    >
                      {selected.output || t("emptyOutput")}
                    </pre>
                  </div>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
