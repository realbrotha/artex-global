"use client";

import * as React from "react";

import { ChevronRightIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { cn } from "@/lib/utils";
import type { Analysis, AnalysisCase, Judgement } from "@/lib/wazuh-api";

import { severityTone, stamp, verdictTone } from "../../assets/_components/case-list";
import { JudgementDetail } from "./judgement-detail";

const COLUMNS =
  "grid grid-cols-[1rem_4.5rem_minmax(0,1.5fr)_minmax(0,1fr)_3rem_3.5rem_6rem_8.5rem] items-center gap-x-3";

// Same identity the server keys verdicts and judgment records by.
const keyOf = (c: AnalysisCase) => `${c.criterion}|${c.actor}`;

interface RunCasesProps {
  readonly detail: Analysis;
  // Judgments made inside this run.
  readonly inRun: Judgement[];
  // The newest recorded judgment of each case key, from any run or screen.
  readonly latest: Record<string, Judgement>;
}

// Every case candidate of a stored run. A row opens the case as it was: its
// facts, the alerts behind it, and the judgment with what the model read.
export function RunCases({ detail, inRun, latest }: RunCasesProps) {
  const t = useTranslations("protectedAssets.history");
  const tc = useTranslations("protectedAssets.cases");
  const [open, setOpen] = React.useState<Set<string>>(new Set());
  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  const ofRun = React.useMemo(() => new Map(inRun.map((j) => [j.case_key, j])), [inRun]);

  return (
    <div className="overflow-x-auto rounded-lg border text-xs">
      <div className="min-w-[50rem]">
        <div className={cn(COLUMNS, "border-b bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground")}>
          <span />
          <span>{t("col.severity")}</span>
          <span>{t("col.case")}</span>
          <span>{t("col.hosts")}</span>
          <span>{t("col.pattern")}</span>
          <span className="text-right">{t("col.alerts")}</span>
          <span>{t("col.verdict")}</span>
          <span>{t("col.origin")}</span>
        </div>
        {detail.cases.map((c) => {
          const expanded = open.has(c.id);
          const mine = ofRun.get(keyOf(c));
          const record = mine ?? latest[keyOf(c)];
          const verdict = c.verdict;
          const timeline = detail.timelines?.[c.id];
          let origin: "known" | "inRun" | "earlier" | "none" = "none";
          if (c.known) origin = "known";
          else if (mine) origin = "inRun";
          else if (verdict || record) origin = "earlier";
          return (
            <div key={c.id} className="border-b last:border-b-0">
              <button
                type="button"
                onClick={() => toggle(c.id)}
                aria-expanded={expanded}
                className={cn(
                  COLUMNS,
                  "w-full px-3 py-1.5 text-left hover:bg-muted/50",
                  expanded && "bg-muted/40",
                  c.known && "opacity-60",
                )}
              >
                <ChevronRightIcon
                  className={cn("size-3.5 text-muted-foreground transition-transform", expanded && "rotate-90")}
                />
                <span>
                  <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", severityTone[c.severity])}>
                    {tc(`severity.${c.severity}`)}
                  </span>
                </span>
                <span className="truncate font-medium" title={verdict?.title ?? c.title ?? c.criterion}>
                  {verdict?.title ?? c.title ?? c.criterion}
                </span>
                <span className="truncate text-muted-foreground" title={c.hosts.join(", ")}>
                  {c.hosts.join(", ")}
                </span>
                <span className="font-mono text-[10px] text-muted-foreground">{c.pattern}</span>
                <span className="text-right tabular-nums">{c.n.toLocaleString()}</span>
                <span className="text-[10px]">
                  {verdict && (
                    <span
                      className={cn(
                        "rounded border px-1.5 py-0.5",
                        verdictTone[verdict.verdict],
                        verdict.stale && "opacity-50",
                      )}
                    >
                      {tc(`verdict.${verdict.verdict}`)}
                    </span>
                  )}
                  {c.judge === "failed" && (
                    <span className="rounded border border-destructive/50 px-1.5 py-0.5 text-destructive">
                      {t("failed")}
                    </span>
                  )}
                </span>
                <span className={cn("truncate", origin === "inRun" ? "text-foreground" : "text-muted-foreground")}>
                  {t(`origin.${origin}`)}
                </span>
              </button>

              {expanded && (
                <div className="grid grid-cols-1 gap-4 border-t bg-muted/10 p-3 pl-10 xl:grid-cols-2">
                  <div className="grid grid-cols-1 content-start gap-3">
                    <section className="grid grid-cols-1 gap-1">
                      <p className="text-[11px] text-muted-foreground">{t("caseInfo")}</p>
                      <p className="break-words">{c.summary}</p>
                      <dl className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-x-2 gap-y-0.5">
                        {(
                          [
                            [t("col.case"), `${c.title ?? ""} ${c.criterion}`.trim()],
                            [tc("field.actor"), c.actor],
                            [tc("field.hosts"), c.hosts.join(", ")],
                            [t("detail.period"), `${stamp(c.first)} ~ ${stamp(c.last)}`],
                            [t("detail.basis"), c.sev_basis],
                            [tc("field.entity"), c.entity],
                            [tc("field.attack"), c.attack.join(", ")],
                            [tc("field.near"), c.near.join(", ")],
                          ] as const
                        )
                          .filter(([, value]) => value)
                          .map(([label, value]) => (
                            <React.Fragment key={label}>
                              <dt className="text-muted-foreground">{label}</dt>
                              <dd className="break-words">{value}</dd>
                            </React.Fragment>
                          ))}
                      </dl>
                      {c.known && <p className="text-muted-foreground">{t("knownNote", { reason: c.known })}</p>}
                    </section>

                    <section className="grid grid-cols-1 gap-1">
                      {!timeline && <p className="text-[11px] text-muted-foreground">{t("noTimeline")}</p>}
                      {timeline && (
                        <>
                          <p className="text-[11px] text-muted-foreground">
                            {timeline.length < c.n
                              ? t("timelineClipped", { shown: timeline.length, total: c.n })
                              : t("timeline", { count: timeline.length })}
                          </p>
                          <ol className="grid max-h-96 grid-cols-1 gap-0.5 overflow-y-auto">
                            {timeline.map((e, index) => (
                              <li
                                key={`${e.t}:${e.rule}:${index}`}
                                className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2 rounded bg-muted/40 px-1.5 py-1"
                              >
                                <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
                                  {stamp(e.t)}
                                </span>
                                <span className="min-w-0">
                                  <span className="break-words">{e.desc}</span>
                                  <span className="block break-all font-mono text-[10px] text-muted-foreground">
                                    {[
                                      e.host,
                                      `rule ${e.rule}`,
                                      `L${e.level}`,
                                      e.actor !== "-" && e.actor,
                                      e.src !== "-" && e.src,
                                    ]
                                      .filter(Boolean)
                                      .join(" · ")}
                                  </span>
                                  {e.object && (
                                    <span className="block break-all font-mono text-[10px]">{e.object}</span>
                                  )}
                                </span>
                              </li>
                            ))}
                          </ol>
                        </>
                      )}
                    </section>
                  </div>

                  <section className="grid grid-cols-1 content-start gap-1.5">
                    <p className="text-[11px] text-muted-foreground">{t("judgement")}</p>
                    {c.judge === "failed" && c.judge_error && (
                      <p className="break-words rounded-md bg-destructive/10 p-2 text-destructive">{c.judge_error}</p>
                    )}
                    {record && !mine && (
                      <p className="text-amber-600 dark:text-amber-400">
                        {t("earlierNote", { when: new Date(record.judged_at).toLocaleString() })}
                      </p>
                    )}
                    {record && <JudgementDetail id={record.id} hideCase />}
                    {!record && verdict && (
                      <div className="grid grid-cols-1 gap-1.5 rounded-md bg-muted/40 p-2">
                        <p className="flex flex-wrap items-center gap-1.5">
                          <span
                            className={cn("rounded border px-1.5 py-0.5 text-[10px]", verdictTone[verdict.verdict])}
                          >
                            {tc(`verdict.${verdict.verdict}`)}
                          </span>
                          <span className="font-medium">{verdict.title}</span>
                        </p>
                        <p className="break-words">{verdict.explain}</p>
                        <ul className="grid grid-cols-1 gap-0.5">
                          {verdict.evidence.map((line, index) => (
                            <li key={`${index}:${line}`} className="break-all font-mono text-[11px]">
                              {line}
                            </li>
                          ))}
                        </ul>
                        {(verdict.response?.length ?? 0) > 0 && (
                          <ul className="list-disc pl-4">
                            {verdict.response?.map((action) => (
                              <li key={action} className="break-words">
                                {action}
                              </li>
                            ))}
                          </ul>
                        )}
                        <p className="text-[11px] text-muted-foreground">
                          {verdict.model} · {new Date(verdict.judged_at).toLocaleString()}
                        </p>
                        <p className="text-[11px] text-amber-600 dark:text-amber-400">{t("noRecord")}</p>
                      </div>
                    )}
                    {!record && !verdict && c.judge !== "failed" && (
                      <p className="text-muted-foreground">{c.known ? t("origin.known") : t("notJudged")}</p>
                    )}
                  </section>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
