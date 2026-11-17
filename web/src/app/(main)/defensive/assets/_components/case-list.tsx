"use client";

import * as React from "react";

import { ChevronRightIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { type CaseVerdict, type SiemCase, type SiemCaseEvent, wazuhApi } from "@/lib/wazuh-api";

export type ListedCase = SiemCase & { sourceId: string; sourceName: string };

export const severityTone: Record<string, string> = {
  Critical: "border-red-600/50 bg-red-600/15 text-red-700 dark:text-red-300",
  High: "border-orange-500/50 bg-orange-500/15 text-orange-700 dark:text-orange-300",
  Medium: "border-amber-500/50 bg-amber-500/15 text-amber-700 dark:text-amber-300",
  Low: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  Info: "border-border bg-muted text-muted-foreground",
};

export const verdictTone: Record<CaseVerdict["verdict"], string> = {
  breach: "border-red-600 bg-red-600 text-white",
  suspicious: "border-orange-500/60 bg-orange-500/15 text-orange-700 dark:text-orange-300",
  attempt: "border-amber-500/60 bg-amber-500/15 text-amber-700 dark:text-amber-300",
  normal: "border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  false_positive: "border-border bg-muted text-muted-foreground",
};

// A current verdict of normal or false positive means nobody needs to act.
export function isCleared(c: SiemCase): boolean {
  const v = c.verdict;
  return Boolean(c.known) || Boolean(v && !v.stale && (v.verdict === "normal" || v.verdict === "false_positive"));
}

// Needs a (new) verdict: never judged, or judged before its latest activity.
export function needsVerdict(c: SiemCase): boolean {
  return !c.known && (!c.verdict || c.verdict.stale);
}

export const stamp = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });

interface CaseDetailProps {
  readonly c: ListedCase;
  // The verdict to show: the stored one, or one just returned by a judge.
  readonly verdict?: CaseVerdict;
  readonly compact?: boolean;
  // Called after a person corrects the verdict, so the owner can reload.
  readonly onCorrected?: () => void;
}

const VERDICTS: CaseVerdict["verdict"][] = ["breach", "suspicious", "attempt", "normal", "false_positive"];

// A person's verdict: replaces the model's, stays until new activity, and is
// shown to the model as a precedent for other cases of the same criterion.
function CorrectVerdict({
  c,
  current,
  onCorrected,
}: {
  readonly c: ListedCase;
  readonly current?: CaseVerdict["verdict"];
  readonly onCorrected?: () => void;
}) {
  const t = useTranslations("protectedAssets.cases.correct");
  const tc = useTranslations("protectedAssets.cases");
  const [open, setOpen] = React.useState(false);
  const [verdict, setVerdict] = React.useState<CaseVerdict["verdict"]>(current ?? "suspicious");
  const [reason, setReason] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState("");

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="justify-self-start text-[11px] text-muted-foreground underline decoration-dotted underline-offset-2 hover:text-foreground"
      >
        {t("open")}
      </button>
    );
  }
  const save = async () => {
    setSaving(true);
    setError("");
    try {
      await wazuhApi.correctCase(c.sourceId, c.id, verdict, reason.trim());
      setOpen(false);
      setReason("");
      onCorrected?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("failed"));
    } finally {
      setSaving(false);
    }
  };
  return (
    <div className="grid grid-cols-1 gap-1.5 rounded-md border border-dashed p-2">
      <p className="text-[11px] text-muted-foreground">{t("hint")}</p>
      <div className="flex flex-wrap gap-1">
        {VERDICTS.map((v) => (
          <button
            key={v}
            type="button"
            onClick={() => setVerdict(v)}
            aria-pressed={verdict === v}
            className={cn(
              "rounded border px-1.5 py-0.5 text-[10px]",
              verdict === v ? verdictTone[v] : "opacity-60 hover:opacity-100",
            )}
          >
            {tc(`verdict.${v}`)}
          </button>
        ))}
      </div>
      <textarea
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder={t("reason")}
        rows={2}
        className="w-full rounded-md border bg-background px-2 py-1 text-xs"
      />
      {error && <p className="break-words text-destructive">{error}</p>}
      <div className="flex gap-2">
        <button
          type="button"
          disabled={saving || reason.trim().length < 5}
          onClick={() => void save()}
          className="rounded-md bg-primary px-2.5 py-1 text-[11px] text-primary-foreground disabled:opacity-50"
        >
          {t("save")}
        </button>
        <button type="button" onClick={() => setOpen(false)} className="px-2 text-[11px] text-muted-foreground">
          {t("cancel")}
        </button>
      </div>
    </div>
  );
}

// Everything behind one case: verdict and evidence, its
// fields and the alert timeline, fetched when the case is first shown.
export function CaseDetail({ c, verdict, compact = false, onCorrected }: CaseDetailProps) {
  const t = useTranslations("protectedAssets.cases");
  const [timeline, setTimeline] = React.useState<SiemCaseEvent[] | "error" | undefined>(undefined);

  React.useEffect(() => {
    let alive = true;
    setTimeline(undefined);
    wazuhApi
      .caseDetail(c.sourceId, c.id)
      .then((full) => alive && setTimeline(full.timeline ?? []))
      .catch(() => alive && setTimeline("error"));
    return () => {
      alive = false;
    };
  }, [c.sourceId, c.id]);

  return (
    <div className="grid grid-cols-1 gap-2 text-xs">
      {verdict && (
        <div className="grid grid-cols-1 gap-1.5 rounded-md bg-muted/40 p-2">
          {verdict.stale && <p className="text-amber-600 dark:text-amber-400">{t("verdictStale")}</p>}
          <ul className="grid grid-cols-1 gap-0.5">
            {verdict.evidence.map((line, index) => (
              <li key={`${index}:${line}`} className="break-all font-mono text-[11px]">
                {line}
              </li>
            ))}
          </ul>
          {verdict.adjust && <p>{t("verdictAdjust", { severity: verdict.severity, reason: verdict.adjust })}</p>}
          {(verdict.response?.length ?? 0) > 0 && (
            <div>
              <p className="text-[10px] text-muted-foreground">{t("verdictResponse")}</p>
              <ul className="list-disc pl-4">
                {verdict.response?.map((action) => (
                  <li key={action} className="break-words">
                    {action}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="text-[10px] text-muted-foreground">
            {t("verdictBy", {
              model: verdict.model || "LLM",
              when: new Date(verdict.judged_at).toLocaleString(),
            })}
            {verdict.method && verdict.method !== "single" && ` · ${t(`method.${verdict.method}`)}`}
          </p>
        </div>
      )}
      {!c.known && <CorrectVerdict c={c} current={verdict?.verdict} onCorrected={onCorrected} />}
      <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
        {(
          [
            ["summary", verdict ? c.summary : ""],
            ["actor", c.actor],
            ["hosts", c.hosts.join(", ")],
            ["period", `${stamp(c.first)} ~ ${stamp(c.last)}`],
            ["basis", c.sev_basis],
            ["entity", c.entity],
            ["attack", c.attack.join(", ")],
            ["known", c.known ?? ""],
            ["near", c.near.join(", ")],
            ["connection", compact ? "" : c.sourceName],
          ] as const
        )
          .filter(([, value]) => value)
          .map(([label, value]) => (
            <div key={label} className="min-w-0">
              <dt className="text-[10px] text-muted-foreground">{t(`field.${label}`)}</dt>
              <dd className="break-words">{value}</dd>
            </div>
          ))}
      </dl>
      {timeline === undefined && <Skeleton className="h-16 w-full" />}
      {timeline === "error" && <p className="text-destructive">{t("timelineFailed")}</p>}
      {Array.isArray(timeline) && (
        <div className="grid grid-cols-1 gap-1">
          <p className="text-[10px] text-muted-foreground">
            {timeline.length < c.n ? t("timelineClipped", { shown: timeline.length, total: c.n }) : t("timeline")}
          </p>
          <ol className="grid grid-cols-1 gap-0.5">
            {timeline.map((e, index) => (
              <li
                key={`${e.t}:${e.rule}:${index}`}
                className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2 rounded bg-muted/40 px-1.5 py-1"
              >
                <span className="font-mono text-[10px] text-muted-foreground tabular-nums">{stamp(e.t)}</span>
                <span className="min-w-0">
                  <span className="break-words">{e.desc}</span>
                  <span className="block break-all font-mono text-[10px] text-muted-foreground">
                    {[e.host, `rule ${e.rule}`, `L${e.level}`, e.actor !== "-" && e.actor, e.src !== "-" && e.src]
                      .filter(Boolean)
                      .join(" · ")}
                  </span>
                  {e.object && <span className="block break-all font-mono text-[10px]">{e.object}</span>}
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

interface CaseListProps {
  readonly cases: ListedCase[];
  // Called after a person corrects a verdict, so the owner can reload.
  readonly onCorrected?: () => void;
  // Narrow layout for the host detail panel.
  readonly compact?: boolean;
}

// Case candidates, most urgent first as the server orders them. A row
// expands to its detail.
export function CaseList({ cases, compact = false, onCorrected }: CaseListProps) {
  const t = useTranslations("protectedAssets.cases");
  const [open, setOpen] = React.useState<string | null>(null);

  return (
    <ul className="grid grid-cols-1 gap-1.5">
      {cases.map((c) => {
        const key = `${c.sourceId}/${c.id}`;
        const expanded = open === key;
        const verdict = c.verdict;
        return (
          <li key={key} className={cn("rounded-lg border text-xs", isCleared({ ...c, verdict }) && "opacity-70")}>
            <button
              type="button"
              onClick={() => setOpen(expanded ? null : key)}
              aria-expanded={expanded}
              className="flex w-full items-start gap-2 px-2.5 py-2 text-left hover:bg-muted/60"
            >
              <ChevronRightIcon
                className={cn(
                  "mt-0.5 size-3.5 shrink-0 text-muted-foreground transition-transform",
                  expanded && "rotate-90",
                )}
              />
              <span className="flex shrink-0 flex-col items-start gap-1">
                <span className={cn("rounded border px-1.5 py-0.5 font-medium text-[10px]", severityTone[c.severity])}>
                  {t(`severity.${c.severity}`)}
                </span>
                {verdict && (
                  <span
                    className={cn(
                      "rounded border px-1.5 py-0.5 font-medium text-[10px]",
                      verdictTone[verdict.verdict],
                      verdict.stale && "opacity-50",
                    )}
                  >
                    {t(`verdict.${verdict.verdict}`)}
                  </span>
                )}
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-baseline gap-x-2">
                  <span className="font-medium">{verdict?.title ?? c.title ?? c.criterion}</span>
                  <span className="font-mono text-[10px] text-muted-foreground">{c.criterion}</span>
                  {c.known && <span className="text-[10px] text-muted-foreground">{t("known")}</span>}
                </span>
                <span className={cn("block break-words text-muted-foreground", !expanded && "line-clamp-2")}>
                  {verdict?.explain ?? c.summary}
                </span>
                {!compact && (
                  <span className="mt-0.5 flex flex-wrap gap-x-3 text-[11px] text-muted-foreground">
                    <span className="break-all">{c.actor}</span>
                    <span>{c.hosts.join(", ")}</span>
                  </span>
                )}
              </span>
              <span className="shrink-0 text-right text-[11px] text-muted-foreground tabular-nums">
                <span className="block">{t("events", { count: c.n })}</span>
                <span className="block">{stamp(c.last)}</span>
              </span>
            </button>
            {expanded && (
              <div className="border-t px-2.5 py-2">
                <CaseDetail c={c} verdict={verdict} compact={compact} />
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
