"use client";

import * as React from "react";

import { CheckIcon, ChevronRightIcon, CircleDashedIcon, SparklesIcon, SquareIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";
import { type Analysis, type AnalysisCase, type AnalysisStep, analysisApi } from "@/lib/wazuh-api";

import { severityTone, verdictTone } from "./case-list";

const POLL_MS = 1000;
const ACTIVE: Analysis["state"][] = ["collecting", "extracting", "judging"];

const seconds = (ms?: number) => ((ms ?? 0) / 1000).toFixed(1);
const needsVerdict = (c: AnalysisCase) => !c.known && (!c.verdict || c.verdict.stale);

function StepIcon({ status }: { readonly status: AnalysisStep["status"] | "pending" }) {
  if (status === "running") return <Spinner className="size-3.5" />;
  if (status === "done") return <CheckIcon className="size-3.5 text-emerald-600 dark:text-emerald-400" />;
  if (status === "failed") return <XIcon className="size-3.5 text-destructive" />;
  return <CircleDashedIcon className="size-3.5 text-muted-foreground" />;
}

function Step({
  status,
  title,
  children,
}: {
  readonly status: AnalysisStep["status"] | "pending";
  readonly title: string;
  readonly children?: React.ReactNode;
}) {
  return (
    <li className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2">
      <span className="mt-0.5">
        <StepIcon status={status} />
      </span>
      <div className="min-w-0">
        <p className={cn("font-medium", (status === "" || status === "pending") && "text-muted-foreground")}>{title}</p>
        {children && <div className="mt-1 grid grid-cols-1 gap-1 text-muted-foreground text-xs">{children}</div>}
      </div>
    </li>
  );
}

interface AnalysisPanelProps {
  readonly sourceId: string;
  // The job as returned when it was started.
  readonly initial: Analysis;
  readonly onClose: () => void;
  // A verdict was stored: the owner's case lists are out of date.
  readonly onJudged: () => void;
}

// Live view of one manual analysis: collect, extract, judge, summary. The
// job runs on the server; this polls it once a second while it is active.
export function AnalysisPanel({ sourceId, initial, onClose, onJudged }: AnalysisPanelProps) {
  const t = useTranslations("protectedAssets.analysis");
  const tc = useTranslations("protectedAssets.cases");
  const [job, setJob] = React.useState(initial);
  const [error, setError] = React.useState("");
  const [open, setOpen] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const active = ACTIVE.includes(job.state);

  React.useEffect(() => setJob(initial), [initial]);

  const judged = React.useRef(0);
  React.useEffect(() => {
    if (!active) return;
    let live = true;
    const timer = setInterval(() => {
      analysisApi
        .get(sourceId, job.id)
        .then((next) => {
          if (!live) return;
          setJob(next);
          setError("");
          if (next.judge_done > judged.current) {
            judged.current = next.judge_done;
            onJudged();
          }
        })
        .catch((e: unknown) => {
          if (live) setError(e instanceof Error ? e.message : t("lost"));
        });
    }, POLL_MS);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [active, sourceId, job.id, onJudged, t]);

  const act = async (call: () => Promise<Analysis>) => {
    setBusy(true);
    try {
      setJob(await call());
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("lost"));
    } finally {
      setBusy(false);
    }
  };

  const pending = job.cases.filter(needsVerdict);
  const known = job.cases.filter((c) => c.known).length;
  const patterns = Object.entries(job.patterns).sort(([a], [b]) => a.localeCompare(b));
  const judgeStatus: AnalysisStep["status"] | "pending" =
    job.state === "judging" ? "running" : job.judge_total > 0 ? "done" : "pending";
  const extracted = job.extract.status === "done";
  const finished = extracted && pending.length === 0 && job.state !== "judging";
  const tally = (verdict: string) =>
    job.cases.filter((c) => !c.known && !c.verdict?.stale && c.verdict?.verdict === verdict).length;
  const verdictCounts = (["breach", "suspicious", "attempt", "normal", "false_positive"] as const)
    .map((v) => [v, tally(v)] as const)
    .filter(([, n]) => n > 0);

  return (
    <aside className="flex w-96 shrink-0 flex-col border-l bg-card text-sm">
      <div className="flex items-start gap-2 border-b p-4">
        <div className="min-w-0 flex-1">
          <p className="font-semibold">{t("title")}</p>
          <p className="truncate text-muted-foreground text-xs">
            {job.label} · {t("window", { days: job.days })}
          </p>
        </div>
        {active && (
          <Button
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={() => void act(() => analysisApi.stop(sourceId, job.id))}
          >
            <SquareIcon />
            {t("stop")}
          </Button>
        )}
        <Button variant="ghost" size="icon-sm" onClick={onClose} aria-label={t("close")}>
          <XIcon />
        </Button>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        {error && <p className="mb-3 break-words text-destructive text-xs">{error}</p>}
        {job.state === "failed" && <p className="mb-3 break-words text-destructive text-xs">{job.error}</p>}
        {job.state === "stopped" && <p className="mb-3 text-amber-600 text-xs dark:text-amber-400">{t("stopped")}</p>}

        <ol className="grid grid-cols-1 gap-4">
          <Step status={job.collect.status} title={t("step.collect")}>
            {job.collect.status === "running" && <p>{t("collecting", { count: job.hosts.length })}</p>}
            {job.collect.status === "done" && (
              <p>
                {t("collected", { count: job.alerts, sec: seconds(job.collect.ms) })}
                {job.capped && ` · ${tc("capped")}`}
              </p>
            )}
          </Step>

          <Step status={job.extract.status} title={t("step.extract")}>
            {job.extract.status === "running" && <p>{t("extracting")}</p>}
            {extracted && (
              <>
                <p>{t("extracted", { rules: job.rules, count: job.cases.length, sec: seconds(job.extract.ms) })}</p>
                {patterns.length > 0 && (
                  <p className="flex flex-wrap gap-1">
                    {patterns.map(([pattern, count]) => (
                      <span key={pattern} className="rounded border px-1.5 py-0.5" title={t(`pattern.${pattern}`)}>
                        {pattern} {t(`pattern.${pattern}`)} · {count}
                      </span>
                    ))}
                  </p>
                )}
                {known > 0 && <p>{t("knownSkipped", { count: known })}</p>}
              </>
            )}
          </Step>

          <Step status={judgeStatus} title={t("step.judge")}>
            {extracted && job.cases.length === 0 && <p>{t("nothing")}</p>}
            {job.state === "judging" && <p>{t("judging", { done: job.judge_done, total: job.judge_total })}</p>}
            {extracted && job.state !== "judging" && pending.length > 0 && (
              <div className="grid grid-cols-1 gap-1.5">
                <p>{t("judgeNote", { count: pending.length })}</p>
                <Button
                  size="sm"
                  className="justify-self-start"
                  disabled={busy}
                  onClick={() => void act(() => analysisApi.judge(sourceId, job.id))}
                >
                  <SparklesIcon />
                  {t("judge", { count: pending.length })}
                </Button>
              </div>
            )}
            {job.cases.length > 0 && (
              <ul className="grid grid-cols-1 gap-1 text-foreground">
                {job.cases.map((c) => {
                  const expanded = open === c.id;
                  const verdict = c.verdict && !c.verdict.stale ? c.verdict : undefined;
                  return (
                    <li key={c.id} className={cn("rounded-md border", c.known && "opacity-60")}>
                      <button
                        type="button"
                        onClick={() => setOpen(expanded ? null : c.id)}
                        aria-expanded={expanded}
                        className="flex w-full items-start gap-1.5 px-2 py-1.5 text-left hover:bg-muted/60"
                      >
                        <span className="mt-0.5 shrink-0">
                          {c.judge === "running" ? (
                            <Spinner className="size-3" />
                          ) : (
                            <ChevronRightIcon
                              className={cn(
                                "size-3 text-muted-foreground transition-transform",
                                expanded && "rotate-90",
                              )}
                            />
                          )}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className={cn("block break-words", !expanded && "line-clamp-2")}>
                            {verdict?.title ?? c.title ?? c.criterion}
                          </span>
                          <span className="mt-0.5 flex flex-wrap items-center gap-1 text-[10px]">
                            <span className={cn("rounded border px-1 py-px", severityTone[c.severity])}>
                              {tc(`severity.${c.severity}`)}
                            </span>
                            {verdict && (
                              <span className={cn("rounded border px-1 py-px", verdictTone[verdict.verdict])}>
                                {tc(`verdict.${verdict.verdict}`)}
                              </span>
                            )}
                            <span className="text-muted-foreground">
                              {c.pattern} · {tc("events", { count: c.n })}
                              {c.known && ` · ${tc("known")}`}
                              {c.judge === "pending" && ` · ${t("queued")}`}
                              {c.judge === "done" && ` · ${t("judgedIn", { sec: seconds(c.judge_ms) })}`}
                            </span>
                          </span>
                          {c.judge === "failed" && (
                            <span className="mt-0.5 block break-words text-[11px] text-destructive">
                              {c.judge_error}
                            </span>
                          )}
                        </span>
                      </button>
                      {expanded && (
                        <div className="grid grid-cols-1 gap-1.5 border-t px-2 py-1.5 text-xs">
                          <p className="break-words">{verdict?.explain ?? c.summary}</p>
                          {verdict && (
                            <ul className="grid grid-cols-1 gap-0.5">
                              {verdict.evidence.map((line) => (
                                <li key={line} className="break-all font-mono text-[11px] text-muted-foreground">
                                  {line}
                                </li>
                              ))}
                            </ul>
                          )}
                          {(verdict?.response?.length ?? 0) > 0 && (
                            <ul className="list-disc pl-4">
                              {verdict?.response?.map((action) => (
                                <li key={action} className="break-words">
                                  {action}
                                </li>
                              ))}
                            </ul>
                          )}
                          <p className="break-all text-[11px] text-muted-foreground">
                            {[c.actor, c.hosts.join(", "), c.criterion].filter(Boolean).join(" · ")}
                          </p>
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </Step>

          <Step status={finished ? "done" : "pending"} title={t("step.summary")}>
            {finished && job.cases.length === 0 && <p>{t("summaryClean", { count: job.alerts })}</p>}
            {finished && job.cases.length > 0 && (
              <p className="flex flex-wrap gap-1">
                {verdictCounts.map(([verdict, count]) => (
                  <span key={verdict} className={cn("rounded border px-1.5 py-0.5", verdictTone[verdict])}>
                    {tc(`verdict.${verdict}`)} {count}
                  </span>
                ))}
                {known > 0 && (
                  <span className="rounded border px-1.5 py-0.5">{t("summaryKnown", { count: known })}</span>
                )}
              </p>
            )}
            {finished && job.model && <p>{t("summaryModel", { model: job.model })}</p>}
          </Step>
        </ol>
      </div>
    </aside>
  );
}
