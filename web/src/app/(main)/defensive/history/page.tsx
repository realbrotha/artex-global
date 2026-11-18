"use client";

import * as React from "react";

import { ArrowLeftIcon, RefreshCwIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { DetailHeader, ListEmpty, LoadError, PageHeader } from "@/components/page";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import { type AnalysisRun, historyApi, type Judgement } from "@/lib/wazuh-api";

import { AnalysisPanel } from "../assets/_components/analysis-panel";
import { JudgementTable } from "./_components/judgement-table";
import { RunAlerts } from "./_components/run-alerts";
import { RunCases } from "./_components/run-cases";

const VIEWS = ["runs", "judgements"] as const;
type View = (typeof VIEWS)[number];
const COLUMNS =
  "grid grid-cols-[9rem_minmax(0,1.4fr)_minmax(0,1fr)_5.5rem_5rem_5rem_4rem_minmax(0,9rem)] items-center gap-x-3";

const stateTone: Record<string, string> = {
  done: "border-success/50 bg-success/10 text-success",
  ready: "border-info/40 bg-info/10 text-info",
  failed: "border-destructive/50 bg-destructive/10 text-destructive",
  stopped: "border-warning/50 bg-warning/10 text-warning",
};

// Analysis history: every manual SIEM log analysis as it ended, and every
// LLM judgment with the prompt the model read and the answer it gave.
export default function HistoryPage() {
  const t = useTranslations("protectedAssets");
  const [view, setView] = React.useState<View>("runs");
  const [runs, setRuns] = React.useState<AnalysisRun[] | null>(null);
  const [judgements, setJudgements] = React.useState<Judgement[] | null>(null);
  const [runId, setRunId] = React.useState<string | null>(null);
  const [run, setRun] = React.useState<{
    run: AnalysisRun;
    judgements: Judgement[];
    latest: Record<string, Judgement>;
  } | null>(null);
  const [runView, setRunView] = React.useState<"cases" | "alerts">("cases");
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    const wanted = new URLSearchParams(window.location.search).get("run");
    if (wanted) setRunId(wanted);
  }, []);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [r, j] = await Promise.all([historyApi.runs(), historyApi.judgements()]);
      setRuns(r.runs);
      setJudgements(j.judgements);
      if (runId) setRun(await historyApi.run(runId));
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [runId, t]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const openRun = (id: string | null) => {
    setRun(null);
    setRunId(id);
  };

  return (
    <div className="flex flex-col gap-4">
      {runId === null ? (
        <PageHeader />
      ) : (
        // 실행 한 건의 상세: 목록으로 돌아가는 버튼은 머리 카드의 작업 버튼.
        <DetailHeader
          title={run?.run.label ?? runId}
          badges={
            run && (
              <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", stateTone[run.run.state])}>
                {t(`history.state.${run.run.state}`)}
              </span>
            )
          }
          actions={
            <Button variant="outline" size="xs" onClick={() => openRun(null)}>
              <ArrowLeftIcon />
              {t("history.back")}
            </Button>
          }
        >
          {run && (
            <p className="text-muted-foreground text-xs">
              {t("history.runSummary", {
                when: new Date(run.run.started_at).toLocaleString(),
                source: run.run.source_name,
                alerts: run.run.alerts,
                cases: run.run.cases,
                judged: run.judgements.length,
              })}
            </p>
          )}
        </DetailHeader>
      )}

      {error && <LoadError message={error} onRetry={() => void load()} />}

      {runId === null && (
        <div className="-mb-2 flex items-center gap-2">
          <Tabs value={view} onValueChange={(v) => setView(v as View)}>
            <TabsList>
              {VIEWS.map((v) => (
                <TabsTrigger key={v} value={v}>
                  {t(`history.view.${v}`)}
                  <span className="ml-1 text-muted-foreground tabular-nums">
                    {(v === "runs" ? runs : judgements)?.length ?? ""}
                  </span>
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
          <Button
            variant="ghost"
            size="icon-sm"
            className="ml-auto"
            onClick={() => void load()}
            disabled={loading}
            aria-label={t("refresh")}
            title={t("refresh")}
          >
            <RefreshCwIcon className={cn(loading && "animate-spin")} />
          </Button>
        </div>
      )}

      {runId === null && view === "runs" && (
        <>
          {runs === null && !error && <Skeleton className="h-64 w-full" />}
          {runs?.length === 0 && <ListEmpty title={t("history.emptyRuns")} />}
          {runs !== null && runs.length > 0 && (
            <div className="overflow-x-auto rounded-xl border bg-card text-xs">
              <div className="min-w-[52rem]">
                <div className={cn(COLUMNS, "border-b bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground")}>
                  <span>{t("history.col.when")}</span>
                  <span>{t("history.col.label")}</span>
                  <span>{t("history.col.source")}</span>
                  <span>{t("history.col.state")}</span>
                  <span className="text-right">{t("history.col.alerts")}</span>
                  <span className="text-right">{t("history.col.cases")}</span>
                  <span className="text-right">{t("history.col.judged")}</span>
                  <span>{t("history.col.model")}</span>
                </div>
                {runs.map((r) => (
                  <button
                    key={r.id}
                    type="button"
                    onClick={() => openRun(r.id)}
                    className={cn(COLUMNS, "w-full border-b px-3 py-2 text-left last:border-b-0 hover:bg-muted/60")}
                  >
                    <span className="text-muted-foreground tabular-nums">
                      {new Date(r.started_at).toLocaleString()}
                    </span>
                    <span className="truncate font-medium" title={r.label}>
                      {r.label}
                    </span>
                    <span className="truncate text-muted-foreground">{r.source_name}</span>
                    <span>
                      <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", stateTone[r.state])}>
                        {t(`history.state.${r.state}`)}
                      </span>
                    </span>
                    <span className="text-right tabular-nums">{r.alerts.toLocaleString()}</span>
                    <span className="text-right tabular-nums">{r.cases.toLocaleString()}</span>
                    <span className="text-right tabular-nums">{r.judged.toLocaleString()}</span>
                    <span className="truncate text-muted-foreground" title={r.model}>
                      {r.model}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {runId === null && view === "judgements" && (
        <>
          {judgements === null && !error && <Skeleton className="h-64 w-full" />}
          {judgements?.length === 0 && <ListEmpty title={t("history.emptyJudgements")} />}
          {judgements !== null && judgements.length > 0 && (
            <JudgementTable judgements={judgements} onOpenRun={openRun} />
          )}
        </>
      )}

      {runId !== null && (
        <>
          {run === null && !error && <Skeleton className="h-64 w-full" />}
          {run?.run.detail && (
            <div className="flex min-h-0 flex-1 flex-col items-start gap-4 lg:flex-row">
              <AnalysisPanel
                sourceId=""
                // The stored detail keeps the state the run ended in.
                initial={{ ...run.run.detail, state: run.run.state }}
                archived
                className="w-full rounded-xl border lg:sticky lg:top-6 lg:h-[calc(var(--main-h)-3rem)] lg:w-[26rem]"
              />
              <div className="grid min-w-0 flex-1 grid-cols-1 content-start gap-2">
                <Tabs value={runView} onValueChange={(v) => setRunView(v as "cases" | "alerts")}>
                  <TabsList>
                    {(["cases", "alerts"] as const).map((v) => (
                      <TabsTrigger key={v} value={v}>
                        {v === "cases"
                          ? t("history.runCases", { count: run.run.detail?.cases.length ?? 0 })
                          : t("history.alerts.tab", { count: run.run.alerts })}
                      </TabsTrigger>
                    ))}
                  </TabsList>
                </Tabs>
                {runView === "alerts" && <RunAlerts runId={run.run.id} detail={run.run.detail} />}
                {runView === "cases" && run.run.detail.cases.length === 0 && <ListEmpty title={t("history.noCases")} />}
                {runView === "cases" && run.run.detail.cases.length > 0 && (
                  <RunCases detail={run.run.detail} inRun={run.judgements} latest={run.latest ?? {}} />
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
