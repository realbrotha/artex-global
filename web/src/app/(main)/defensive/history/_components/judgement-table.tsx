"use client";

import * as React from "react";

import { ChevronRightIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { cn } from "@/lib/utils";
import type { Judgement } from "@/lib/wazuh-api";

import { verdictTone } from "../../assets/_components/case-list";
import { JudgementDetail } from "./judgement-detail";

const COLUMNS =
  "grid grid-cols-[1rem_8.5rem_minmax(0,1.4fr)_minmax(0,1fr)_6rem_minmax(0,9rem)_3rem_3.5rem_5rem] items-center gap-x-3";

interface JudgementTableProps {
  readonly judgements: Judgement[];
  // Called with a run id when the origin cell of a run judgment is clicked.
  readonly onOpenRun?: (runId: string) => void;
}

// Judgments newest first; a row opens what the model was sent and answered.
export function JudgementTable({ judgements, onOpenRun }: JudgementTableProps) {
  const t = useTranslations("protectedAssets.history");
  const tc = useTranslations("protectedAssets.cases");
  const [open, setOpen] = React.useState<number | null>(null);

  return (
    <div className="overflow-x-auto rounded-lg border text-xs">
      <div className="min-w-[56rem]">
        <div className={cn(COLUMNS, "border-b bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground")}>
          <span />
          <span>{t("col.when")}</span>
          <span>{t("col.case")}</span>
          <span>{t("col.hosts")}</span>
          <span>{t("col.verdict")}</span>
          <span>{t("col.model")}</span>
          <span className="text-right">{t("col.tries")}</span>
          <span className="text-right">{t("col.ms")}</span>
          <span>{t("col.origin")}</span>
        </div>
        {judgements.map((j) => {
          const expanded = open === j.id;
          return (
            <div key={j.id} className="border-b last:border-b-0">
              <div className={cn(COLUMNS, "px-3 py-1.5 hover:bg-muted/50", expanded && "bg-muted/40")}>
                <button
                  type="button"
                  onClick={() => setOpen(expanded ? null : j.id)}
                  aria-expanded={expanded}
                  className="col-span-8 grid grid-cols-subgrid items-center text-left"
                >
                  <ChevronRightIcon
                    className={cn("size-3.5 text-muted-foreground transition-transform", expanded && "rotate-90")}
                  />
                  <span className="text-muted-foreground tabular-nums">{new Date(j.judged_at).toLocaleString()}</span>
                  <span className="truncate font-medium" title={j.verdict?.title ?? j.case.title ?? j.case.criterion}>
                    {j.verdict?.title ?? j.case.title ?? j.case.criterion}
                  </span>
                  <span className="truncate text-muted-foreground" title={j.case.hosts.join(", ")}>
                    {j.case.hosts.join(", ")}
                  </span>
                  <span className="text-[10px]">
                    {j.verdict ? (
                      <span className={cn("rounded border px-1.5 py-0.5", verdictTone[j.verdict.verdict])}>
                        {tc(`verdict.${j.verdict.verdict}`)}
                      </span>
                    ) : (
                      <span className="rounded border border-destructive/50 px-1.5 py-0.5 text-destructive">
                        {t("failed")}
                      </span>
                    )}
                  </span>
                  <span className="truncate text-muted-foreground" title={j.model}>
                    {j.model}
                  </span>
                  <span className={cn("text-right tabular-nums", j.tries > 1 && "text-amber-600 dark:text-amber-400")}>
                    {t("tries", { count: j.tries })}
                  </span>
                  <span className="text-right text-muted-foreground tabular-nums">
                    {t("sec", { sec: (j.ms / 1000).toFixed(1) })}
                  </span>
                </button>
                {j.run_id && onOpenRun ? (
                  <button
                    type="button"
                    onClick={() => onOpenRun(j.run_id)}
                    className="truncate text-left underline decoration-dotted underline-offset-2 hover:text-primary"
                  >
                    {t("originRun")}
                  </button>
                ) : (
                  <span className="truncate text-muted-foreground">
                    {j.run_id ? t("originRun") : t("originDirect")}
                  </span>
                )}
              </div>
              {expanded && (
                <div className="border-t bg-muted/10 p-3 pl-10">
                  <JudgementDetail id={j.id} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
