"use client";

import * as React from "react";

import {
  CheckIcon,
  ChevronRightIcon,
  CircleDashedIcon,
  CircleMinusIcon,
  CirclePauseIcon,
  SquareIcon,
  XIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";
import { type Analysis, type AnalysisCase, type AnalysisStep, analysisApi } from "@/lib/wazuh-api";

import { severityTone, stamp, verdictTone } from "./case-list";

const POLL_MS = 1000;
const ACTIVE: Analysis["state"][] = ["collecting", "extracting", "judging"];

const seconds = (ms?: number) => ((ms ?? 0) / 1000).toFixed(1);
const needsVerdict = (c: AnalysisCase) => !c.known && (!c.verdict || c.verdict.stale);
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
const FLAGGED = ["breach", "suspicious", "attempt"];
const BRIEF = 5;

// One labelled fact of a step: "label  value".
function Fact({ label, children }: { readonly label: string; readonly children: React.ReactNode }) {
  return (
    <p className="grid grid-cols-[4.5rem_minmax(0,1fr)] gap-x-2">
      <span className="text-muted-foreground/80">{label}</span>
      <span className="min-w-0 break-words text-foreground">{children}</span>
    </p>
  );
}

// pending: not reached yet. waiting: reached, needs the user's go-ahead.
// skipped: the run ended without doing it.
type StepStatus = AnalysisStep["status"] | "pending" | "waiting" | "skipped";

function StepIcon({ status }: { readonly status: StepStatus }) {
  if (status === "waiting") return <CirclePauseIcon className="size-3.5 text-amber-600 dark:text-amber-400" />;
  if (status === "skipped") return <CircleMinusIcon className="size-3.5 text-muted-foreground" />;
  if (status === "running") return <Spinner className="size-3.5" />;
  if (status === "done") return <CheckIcon className="size-3.5 text-emerald-600 dark:text-emerald-400" />;
  if (status === "failed") return <XIcon className="size-3.5 text-destructive" />;
  return <CircleDashedIcon className="size-3.5 text-muted-foreground" />;
}

function Step({
  status,
  title,
  note,
  children,
}: {
  readonly status: StepStatus;
  readonly title: string;
  // Why the step has no tick, next to its title.
  readonly note?: string;
  readonly children?: React.ReactNode;
}) {
  return (
    <li className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2">
      <span className="mt-0.5">
        <StepIcon status={status} />
      </span>
      <div className="min-w-0">
        <p className={cn("font-medium", (status === "" || status === "pending") && "text-muted-foreground")}>
          {title}
          {note && (
            <span
              className={cn(
                "ml-1.5 font-normal text-[11px]",
                status === "waiting" ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground",
              )}
            >
              {note}
            </span>
          )}
        </p>
        {children && <div className="mt-1 grid grid-cols-1 gap-1 text-muted-foreground text-xs">{children}</div>}
      </div>
    </li>
  );
}

interface AnalysisPanelProps {
  readonly sourceId: string;
  // The job as returned when it was started.
  readonly initial: Analysis;
  readonly onClose?: () => void;
  // A verdict was stored: the owner's case lists are out of date.
  readonly onJudged?: () => void;
  // A stored run from the history: shown as it ended, with no actions.
  readonly archived?: boolean;
  readonly className?: string;
}

// Live view of one manual analysis: collect, extract, judge, summary. The
// job runs on the server; this polls it once a second while it is active.
export function AnalysisPanel({
  sourceId,
  initial,
  onClose,
  onJudged,
  archived = false,
  className,
}: AnalysisPanelProps) {
  const t = useTranslations("protectedAssets.analysis");
  const tc = useTranslations("protectedAssets.cases");
  const [job, setJob] = React.useState(initial);
  const [error, setError] = React.useState("");
  const [open, setOpen] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  // Breakdowns show their first rows; the rest on request.
  const [allRules, setAllRules] = React.useState(false);
  const [allHosts, setAllHosts] = React.useState(false);
  // A run that just finished extracting is judged by the server next, unless
  // it left a note saying why not: keep watching it until then.
  const active = !archived && (ACTIVE.includes(job.state) || (job.state === "ready" && !job.judge_note));

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
            onJudged?.();
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
  const extracted = job.extract.status === "done";
  const finished = extracted && pending.length === 0 && job.state !== "judging";
  // Judging is the one step that waits for a go-ahead, so it can end a run
  // undone: say so instead of leaving it looking unreached.
  let judgeStatus: StepStatus = "pending";
  if (job.state === "judging") judgeStatus = "running";
  else if (finished) judgeStatus = "done";
  else if (extracted) judgeStatus = archived ? "skipped" : "waiting";
  let judgeNote: string | undefined;
  if (judgeStatus === "waiting" || judgeStatus === "skipped") {
    judgeNote = job.judge_total > 0 ? t("stepNote.partial", { count: pending.length }) : t(`stepNote.${judgeStatus}`);
  }
  const summaryStatus: StepStatus = finished || (archived && extracted) ? "done" : "pending";
  const tally = (verdict: string) =>
    job.cases.filter((c) => !c.known && !c.verdict?.stale && c.verdict?.verdict === verdict).length;
  const verdictCounts = (["breach", "suspicious", "attempt", "normal", "false_positive"] as const)
    .map((v) => [v, tally(v)] as const)
    .filter(([, n]) => n > 0);
  const severities = SEVERITIES.map(
    (s) => [s, job.cases.filter((c) => !c.known && c.severity === s).length] as const,
  ).filter(([, n]) => n > 0);
  const caseHosts = new Set(job.cases.flatMap((c) => c.hosts)).size;
  const mostAlerts = job.top_rules[0]?.count ?? 1;
  const byHost = job.alert_by_host ?? [];
  const mostOnHost = byHost[0]?.count ?? 1;
  const more = "justify-self-start text-[11px] underline decoration-dotted underline-offset-2 hover:text-foreground";
  // This run's verdict calls.
  const ran = job.cases.filter((c) => c.judge === "done" || c.judge === "failed");
  const ranFailed = ran.filter((c) => c.judge === "failed").length;
  const judgeMs = ran.reduce((n, c) => n + (c.judge_ms ?? 0), 0);
  // Verdicts shown here that an earlier run or screen produced.
  const reused = job.cases.filter((c) => !c.known && c.verdict && !c.verdict.stale && c.judge !== "done");
  const reusedCounts = (["breach", "suspicious", "attempt", "normal", "false_positive"] as const)
    .map((v) => [v, reused.filter((c) => c.verdict?.verdict === v).length] as const)
    .filter(([, n]) => n > 0);
  // Cases a person should look at: judged breach, suspicious or attempt.
  const flagged = job.cases.filter((c) => !c.known && !c.verdict?.stale && FLAGGED.includes(c.verdict?.verdict ?? ""));

  return (
    <aside className={cn("flex w-96 shrink-0 flex-col border-l bg-card text-sm", className)}>
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
        {onClose && (
          <Button variant="ghost" size="icon-sm" onClick={onClose} aria-label={t("close")}>
            <XIcon />
          </Button>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        {error && <p className="mb-3 break-words text-destructive text-xs">{error}</p>}
        {job.state === "failed" && <p className="mb-3 break-words text-destructive text-xs">{job.error}</p>}
        {job.state === "stopped" && <p className="mb-3 text-amber-600 text-xs dark:text-amber-400">{t("stopped")}</p>}

        <ol className="grid grid-cols-1 gap-4">
          <Step status={job.collect.status} title={t("step.collect")}>
            {job.collect.status === "running" && <p>{t("collecting", { count: job.hosts.length })}</p>}
            {job.collect.status === "done" && (
              <>
                <Fact label={t("fact.target")}>
                  {t("target", { count: job.hosts.length })} · {t("window", { days: job.days })}
                </Fact>
                <Fact label={t("fact.alerts")}>
                  {t("collected", { count: job.alerts, sec: seconds(job.collect.ms) })}
                  {job.capped && ` · ${tc("capped")}`}
                </Fact>
                {job.alert_from && job.alert_to && (
                  <Fact label={t("fact.span")}>
                    {t("alertSpan", { hosts: job.alert_hosts, from: stamp(job.alert_from), to: stamp(job.alert_to) })}
                  </Fact>
                )}
                <Fact label={t("fact.posture")}>{t("checked", { count: job.checked_hosts })}</Fact>
                {job.top_rules.length > 0 && (
                  <div className="grid grid-cols-1 gap-0.5">
                    <p className="text-muted-foreground/80">{t("topRules")}</p>
                    {job.top_rules.slice(0, allRules ? undefined : BRIEF).map((rule) => (
                      <p
                        key={rule.id}
                        className="grid grid-cols-[3rem_minmax(0,1fr)_3rem_auto] items-center gap-x-1.5"
                        title={`${rule.id} · L${rule.level} · ${rule.desc}`}
                      >
                        <span className="font-mono text-[10px]">{rule.id}</span>
                        <span className="truncate text-foreground">{rule.desc}</span>
                        <span className="h-1 overflow-hidden rounded-full bg-muted">
                          <span
                            className="block h-full rounded-full bg-sky-500"
                            style={{ width: `${(rule.count / mostAlerts) * 100}%` }}
                          />
                        </span>
                        <span className="text-right tabular-nums">{rule.count.toLocaleString()}</span>
                      </p>
                    ))}
                    {job.top_rules.length > BRIEF && (
                      <button type="button" className={more} onClick={() => setAllRules(!allRules)}>
                        {allRules ? t("showLess") : t("showAll", { count: job.top_rules.length })}
                      </button>
                    )}
                  </div>
                )}
                {byHost.length > 0 && (
                  <div className="grid grid-cols-1 gap-0.5">
                    <p className="text-muted-foreground/80">{t("byHost")}</p>
                    {byHost.slice(0, allHosts ? undefined : BRIEF).map((row) => (
                      <p key={row.host} className="grid grid-cols-[minmax(0,1fr)_3rem_auto] items-center gap-x-1.5">
                        <span className="truncate text-foreground" title={row.host}>
                          {row.host}
                        </span>
                        <span className="h-1 overflow-hidden rounded-full bg-muted">
                          <span
                            className="block h-full rounded-full bg-sky-500"
                            style={{ width: `${(row.count / mostOnHost) * 100}%` }}
                          />
                        </span>
                        <span className="text-right tabular-nums">{row.count.toLocaleString()}</span>
                      </p>
                    ))}
                    {byHost.length > BRIEF && (
                      <button type="button" className={more} onClick={() => setAllHosts(!allHosts)}>
                        {allHosts ? t("showLess") : t("showAll", { count: byHost.length })}
                      </button>
                    )}
                  </div>
                )}
              </>
            )}
          </Step>

          <Step status={job.extract.status} title={t("step.extract")}>
            {job.extract.status === "running" && <p>{t("extracting")}</p>}
            {extracted && (
              <>
                <Fact label={t("fact.rules")}>
                  {t("extracted", { rules: job.rules, count: job.cases.length, sec: seconds(job.extract.ms) })}
                </Fact>
                {severities.length > 0 && (
                  <Fact label={t("fact.severity")}>
                    <span className="flex flex-wrap gap-1 text-[10px]">
                      {severities.map(([severity, count]) => (
                        <span key={severity} className={cn("rounded border px-1.5 py-0.5", severityTone[severity])}>
                          {tc(`severity.${severity}`)} {count}
                        </span>
                      ))}
                    </span>
                  </Fact>
                )}
                {job.cases.length > 0 && <Fact label={t("fact.hosts")}>{t("caseHosts", { count: caseHosts })}</Fact>}
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
                {job.seen_note && <p>{t("seenNote", { note: job.seen_note })}</p>}
              </>
            )}
          </Step>

          <Step status={judgeStatus} title={t("step.judge")} note={judgeNote}>
            {extracted && job.cases.length === 0 && <p>{t("nothing")}</p>}
            {extracted && job.cases.length > 0 && job.state !== "judging" && (
              <>
                <Fact label={t("fact.thisRun")}>
                  {ran.length > 0
                    ? t("judgedRun", { done: ran.length - ranFailed, failed: ranFailed })
                    : t("judgeNotRun")}
                </Fact>
                <Fact label={t("fact.reused")}>
                  {reused.length === 0 ? (
                    t("caseCount", { count: 0 })
                  ) : (
                    <span className="flex flex-wrap items-center gap-1 text-[10px]">
                      <span className="text-xs">{t("caseCount", { count: reused.length })}</span>
                      {reusedCounts.map(([verdict, count]) => (
                        <span key={verdict} className={cn("rounded border px-1.5 py-0.5", verdictTone[verdict])}>
                          {tc(`verdict.${verdict}`)} {count}
                        </span>
                      ))}
                    </span>
                  )}
                </Fact>
                <Fact label={t("fact.unjudged")}>{t("caseCount", { count: pending.length })}</Fact>
                {known > 0 && <Fact label={tc("known")}>{t("caseCount", { count: known })}</Fact>}
              </>
            )}
            {job.state === "judging" && (
              <>
                <p>{t("judging", { done: job.judge_done, total: job.judge_total })}</p>
                <span className="block h-1 overflow-hidden rounded-full bg-muted">
                  <span
                    className="block h-full rounded-full bg-primary transition-[width]"
                    style={{ width: `${(job.judge_done / Math.max(1, job.judge_total)) * 100}%` }}
                  />
                </span>
              </>
            )}
            {ran.length > 0 && (
              <p>
                {t("judgeStats", {
                  done: ran.length - ranFailed,
                  failed: ranFailed,
                  sec: seconds(judgeMs / ran.length),
                })}
                {job.model && ` · ${job.model}`}
              </p>
            )}
            {job.judge_note && <p className="text-amber-600 dark:text-amber-400">{job.judge_note}</p>}
            {(job.reviewed ?? 0) > 0 && (
              <Fact label={t("fact.review")}>
                {t("reviewed", { count: job.reviewed ?? 0, changed: job.review_changed ?? 0 })}
              </Fact>
            )}
            {job.gap_note && <p>{job.gap_note}</p>}
            {((job.debated ?? 0) > 0 || (job.fallback ?? 0) > 0 || (job.deferred ?? 0) > 0) && (
              <Fact label={t("fact.method")}>
                {[
                  (job.debated ?? 0) > 0 && t("methodDebated", { count: job.debated ?? 0 }),
                  (job.fallback ?? 0) > 0 && t("methodFallback", { count: job.fallback ?? 0 }),
                  (job.deferred ?? 0) > 0 && t("methodDeferred", { count: job.deferred ?? 0 }),
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </Fact>
            )}
            {!archived && job.cases.length > 0 && (
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
                            {verdict?.method && verdict.method !== "single" && (
                              <span className="rounded border border-violet-500/50 px-1 py-px text-violet-700 dark:text-violet-300">
                                {tc(`method.${verdict.method}`)}
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

          <Step status={summaryStatus} title={t("step.summary")}>
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
            {extracted && !finished && job.cases.length > 0 && (
              <p>{t("summaryPending", { count: job.cases.length, pending: pending.length })}</p>
            )}
            {finished && flagged.length > 0 && (
              <div className="grid grid-cols-1 gap-0.5">
                <p className="text-muted-foreground/80">{t("summaryFlagged", { count: flagged.length })}</p>
                <ul className="list-disc pl-4 text-foreground">
                  {flagged.map((c) => (
                    <li key={c.id} className="break-words">
                      {c.verdict?.title ?? c.title ?? c.criterion}
                      <span className="text-muted-foreground"> · {c.hosts.join(", ")}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {extracted && (
              <p>
                {t("summaryTime", {
                  collect: seconds(job.collect.ms),
                  extract: seconds(job.extract.ms),
                  judge: seconds(judgeMs),
                })}
              </p>
            )}
            {finished && job.model && <p>{t("summaryModel", { model: job.model })}</p>}
          </Step>
        </ol>
      </div>
    </aside>
  );
}
