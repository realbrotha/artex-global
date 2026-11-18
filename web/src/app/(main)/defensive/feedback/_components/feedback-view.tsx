"use client";

import * as React from "react";

import Link from "next/link";

import { RefreshCwIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { ListEmpty, LoadError } from "@/components/page";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { type CaseVerdict, type FeedbackSource, feedbackApi } from "@/lib/wazuh-api";

import { verdictTone } from "../../assets/_components/case-list";

const VERDICTS: CaseVerdict["verdict"][] = ["breach", "suspicious", "attempt", "normal", "false_positive"];
const METHODS = ["single", "debate", "fallback", "human"] as const;
const COLUMNS = "grid grid-cols-[minmax(0,1.6fr)_3.5rem_minmax(0,2fr)_4rem_4rem_4rem_4rem] items-center gap-x-3";

// Solid fills: the light verdict badges are too faint as bar segments.
const verdictBar: Record<CaseVerdict["verdict"], string> = {
  breach: "bg-danger",
  suspicious: "bg-caution",
  attempt: "bg-warning/40",
  normal: "bg-success",
  false_positive: "bg-muted-foreground",
};

const signalTone: Record<string, string> = {
  corrected: "border-primary/50 bg-primary/10 text-primary",
  false_positive_heavy: "border-warning/50 bg-warning/10 text-warning",
  unstable: "border-caution/50 bg-caution/10 text-caution",
  normal_repeat: "border-success/50 bg-success/10 text-success",
};

// Judging feedback: how the automatic judging has been doing per detection
// criterion, what people corrected, and what that suggests changing.
// header 를 주면 새로고침 아이콘 버튼을 넘겨 페이지 머리에 붙인다. 품질 화면의 탭에서는 생략.
export function FeedbackView({ header }: { readonly header?: (refresh: React.ReactNode) => React.ReactNode }) {
  const t = useTranslations("siemFeedback");
  const tc = useTranslations("protectedAssets.cases");
  const [data, setData] = React.useState<{ sources: FeedbackSource[]; window_days: number } | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      setData(await feedbackApi.get());
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

  return (
    <div className="flex flex-col gap-4">
      {header?.(
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => void load()}
          disabled={loading}
          aria-label={t("refresh")}
          title={t("refresh")}
        >
          <RefreshCwIcon className={cn(loading && "animate-spin")} />
        </Button>,
      )}

      {error && <LoadError message={error} onRetry={() => void load()} />}
      {data === null && !error && <Skeleton className="h-96 w-full" />}
      {data?.sources.length === 0 && <ListEmpty title={t("empty")} />}

      {data?.sources.map((source) => {
        const total = Object.values(source.methods).reduce((n, v) => n + v, 0);
        return (
          <div key={source.id} className="grid grid-cols-1 gap-4">
            {data.sources.length > 1 && <h2 className="font-medium">{source.name}</h2>}

            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              {METHODS.map((m) => (
                <div key={m} className="rounded-xl border bg-card px-4 py-3">
                  <p className="text-[11px] text-muted-foreground">{t(`method.${m}`)}</p>
                  <p className="font-semibold text-xl tabular-nums">{(source.methods[m] ?? 0).toLocaleString()}</p>
                  <p className="text-[11px] text-muted-foreground">
                    {total > 0 ? `${Math.round(((source.methods[m] ?? 0) / total) * 100)}%` : "—"} ·{" "}
                    {t(`methodHint.${m}`)}
                  </p>
                </div>
              ))}
            </div>

            <section className="grid grid-cols-1 gap-2">
              <h3 className="font-medium text-sm">{t("signals", { count: source.signals.length })}</h3>
              {source.signals.length === 0 ? (
                <p className="rounded-lg border border-dashed p-4 text-center text-muted-foreground text-xs">
                  {t("noSignals")}
                </p>
              ) : (
                <ul className="grid grid-cols-1 gap-1.5 text-xs">
                  {source.signals.map((s) => (
                    <li
                      key={`${s.kind}:${s.criterion}:${s.case_key ?? ""}`}
                      className="grid grid-cols-1 gap-1 rounded-lg border p-2.5 sm:grid-cols-[9rem_minmax(0,1fr)]"
                    >
                      <span>
                        <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", signalTone[s.kind])}>
                          {t(`signal.${s.kind}.label`)}
                        </span>
                      </span>
                      <span className="grid grid-cols-1 gap-0.5">
                        <span className="font-medium">
                          {s.title || s.criterion}{" "}
                          <span className="font-mono font-normal text-[10px] text-muted-foreground">{s.criterion}</span>
                          {s.case_key && (
                            <span className="ml-1 font-normal text-muted-foreground">
                              · {s.case_key.split("|").slice(1).join("|")}
                            </span>
                          )}
                        </span>
                        <span className="text-muted-foreground">
                          {t(`signal.${s.kind}.detail`, { count: s.count, of: s.of })}
                        </span>
                        <span>{t(`signal.${s.kind}.action`)}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="grid grid-cols-1 gap-2">
              <h3 className="font-medium text-sm">{t("criteria", { count: source.criteria.length })}</h3>
              <div className="overflow-x-auto rounded-xl border bg-card text-xs">
                <div className="min-w-[48rem]">
                  <div className={cn(COLUMNS, "border-b bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground")}>
                    <span>{t("col.criterion")}</span>
                    <span className="text-right">{t("col.cases")}</span>
                    <span>{t("col.verdicts")}</span>
                    <span className="text-right">{t("col.judged")}</span>
                    <span className="text-right">{t("col.debated")}</span>
                    <span className="text-right">{t("col.fallback")}</span>
                    <span className="text-right">{t("col.corrected")}</span>
                  </div>
                  {source.criteria.map((r) => (
                    <div key={r.criterion} className={cn(COLUMNS, "border-b px-3 py-1.5 last:border-b-0")}>
                      <span className="truncate" title={r.title || r.criterion}>
                        {r.title || r.criterion}{" "}
                        <span className="font-mono text-[10px] text-muted-foreground">{r.criterion}</span>
                      </span>
                      <span className="text-right tabular-nums">{r.cases}</span>
                      <span className="flex h-3 overflow-hidden rounded-sm bg-muted">
                        {VERDICTS.filter((v) => (r.verdicts[v] ?? 0) > 0).map((v) => (
                          <span
                            key={v}
                            title={`${tc(`verdict.${v}`)} ${r.verdicts[v]}`}
                            className={cn("block h-full", verdictBar[v])}
                            style={{ width: `${((r.verdicts[v] ?? 0) / Math.max(1, r.cases)) * 100}%` }}
                          />
                        ))}
                      </span>
                      <span className="text-right tabular-nums">{r.judgements}</span>
                      <span className={cn("text-right tabular-nums", r.debated > 0 && "text-caution")}>
                        {r.debated}
                      </span>
                      <span className={cn("text-right tabular-nums", r.fallback > 0 && "text-caution")}>
                        {r.fallback}
                      </span>
                      <span className={cn("text-right tabular-nums", r.corrected > 0 && "text-primary")}>
                        {r.corrected}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              <p className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                {VERDICTS.map((v) => (
                  <span key={v} className="flex items-center gap-1">
                    <span className={cn("inline-block size-2.5 rounded-sm", verdictBar[v])} />
                    {tc(`verdict.${v}`)}
                  </span>
                ))}
              </p>
            </section>

            <section className="grid grid-cols-1 gap-2">
              <h3 className="font-medium text-sm">{t("corrections", { count: source.corrections.length })}</h3>
              {source.corrections.length === 0 ? (
                <p className="rounded-lg border border-dashed p-4 text-center text-muted-foreground text-xs">
                  {t("noCorrections")}{" "}
                  <Link href="/defensive/detections" className="underline underline-offset-2">
                    {t("howToCorrect")}
                  </Link>
                </p>
              ) : (
                <ul className="grid grid-cols-1 gap-1.5 text-xs">
                  {source.corrections.map((c) => (
                    <li key={c.id} className="grid grid-cols-1 gap-0.5 rounded-lg border p-2.5">
                      <span className="flex flex-wrap items-center gap-1.5">
                        {c.from && (
                          <>
                            <span
                              className={cn(
                                "rounded border px-1.5 py-0.5 text-[10px] line-through opacity-60",
                                verdictTone[c.from as CaseVerdict["verdict"]],
                              )}
                            >
                              {tc(`verdict.${c.from}`)}
                            </span>
                            →
                          </>
                        )}
                        <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", verdictTone[c.to])}>
                          {tc(`verdict.${c.to}`)}
                        </span>
                        <span className="font-mono text-[10px] text-muted-foreground">{c.criterion}</span>
                        <span className="text-muted-foreground">{c.actor}</span>
                        <span className="ml-auto text-[11px] text-muted-foreground">
                          {new Date(c.created_at).toLocaleString()}
                        </span>
                      </span>
                      <span className="break-words">{c.reason}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        );
      })}
    </div>
  );
}
