"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowUpRightIcon, ChevronRightIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { cn } from "@/lib/utils";
import { hostDetailUrl } from "@/lib/wazuh-api";

import type { CaseGroup, GroupBy } from "../../assets/_components/case-groups";
import { isCleared, type ListedCase, severityTone, stamp, verdictTone } from "../../assets/_components/case-list";

const GROUP_PAGE = 50;
const CASE_PAGE = 20;
const FLAGGED = ["breach", "suspicious", "attempt"] as const;
// Columns of the case lines inside an opened group.
const CASE_COLUMNS =
  "grid grid-cols-[4.5rem_minmax(0,1.2fr)_minmax(0,1.6fr)_3.5rem_5.5rem_6.5rem_1rem] items-center gap-x-3";
const COLUMNS = "grid grid-cols-[1rem_1rem_4.5rem_minmax(0,1fr)_4rem_4rem_4.5rem_7.5rem_6rem] items-center gap-x-2";

export const caseKey = (c: ListedCase) => `${c.sourceId}/${c.id}`;

interface GroupedCasesProps {
  readonly groups: CaseGroup[];
  readonly by: GroupBy;
  readonly selected: string | null;
  readonly onSelect: (c: ListedCase) => void;
  readonly checked: ReadonlySet<string>;
  readonly onCheck: (keys: string[], on: boolean) => void;
}

// The cases as a dense table: one row per group, expanding to one line per
// case. A case line opens its detail beside the table.
export function GroupedCases({ groups, by, selected, onSelect, checked, onCheck }: GroupedCasesProps) {
  const t = useTranslations("protectedAssets");
  const [open, setOpen] = React.useState<Set<string>>(new Set());
  const [groupLimit, setGroupLimit] = React.useState(GROUP_PAGE);
  const [caseLimit, setCaseLimit] = React.useState<Record<string, number>>({});
  const toggle = (key: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (!next.delete(key)) next.add(key);
      return next;
    });

  const shown = groups.slice(0, groupLimit);
  const allChecked = shown.length > 0 && shown.every((g) => checked.has(g.key));
  const moreButton = "w-full border-t px-3 py-2 text-center text-muted-foreground text-xs hover:bg-muted";

  return (
    <div className="@container overflow-x-auto rounded-lg border text-xs">
      <div className="min-w-[42rem]">
        <div className={cn(COLUMNS, "border-b bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground")}>
          <input
            type="checkbox"
            aria-label={t("detections.selectAll")}
            checked={allChecked}
            onChange={(e) =>
              onCheck(
                shown.map((g) => g.key),
                e.target.checked,
              )
            }
          />
          <span />
          <span>{t("detections.col.severity")}</span>
          <span>{t(`detections.col.name.${by}`)}</span>
          <span className="text-right">{t("detections.col.hosts")}</span>
          <span className="text-right">{t("detections.col.cases")}</span>
          <span className="text-right">{t("detections.col.events")}</span>
          <span>{t("detections.col.state")}</span>
          <span className="text-right">{t("detections.col.last")}</span>
        </div>

        {shown.map((group) => {
          const expanded = open.has(group.key);
          const flagged = FLAGGED.map(
            (v) =>
              [v, group.cases.filter((c) => c.verdict && !c.verdict.stale && c.verdict.verdict === v).length] as const,
          ).filter(([, n]) => n > 0);
          const limit = caseLimit[group.key] ?? CASE_PAGE;
          const name = by === "cluster" ? group.label || t("detections.noCluster") : (group.title ?? group.label);
          return (
            <div key={group.key} className="border-b last:border-b-0">
              <div
                className={cn(
                  COLUMNS,
                  "px-3 py-2 hover:bg-muted/50",
                  expanded && "bg-muted/50 font-medium",
                  group.live === 0 && "opacity-60",
                )}
              >
                <input
                  type="checkbox"
                  aria-label={t("detections.selectGroup", { name })}
                  checked={checked.has(group.key)}
                  onChange={(e) => onCheck([group.key], e.target.checked)}
                />
                <button
                  type="button"
                  onClick={() => toggle(group.key)}
                  aria-expanded={expanded}
                  className="col-span-8 grid grid-cols-subgrid items-center text-left"
                >
                  <ChevronRightIcon
                    className={cn("size-3.5 text-muted-foreground transition-transform", expanded && "rotate-90")}
                  />
                  <span>
                    {group.live > 0 && (
                      <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", severityTone[group.worst])}>
                        {t(`cases.severity.${group.worst}`)}
                      </span>
                    )}
                  </span>
                  <span className="flex min-w-0 items-baseline gap-2">
                    <span className="truncate font-medium" title={name}>
                      {name}
                    </span>
                    {by === "rule" && group.title && (
                      <span className="@4xl:inline hidden shrink-0 font-mono text-[10px] text-muted-foreground">
                        {group.label}
                      </span>
                    )}
                  </span>
                  <span className="text-right tabular-nums">{group.hosts.toLocaleString()}</span>
                  <span className="text-right tabular-nums">{group.cases.length.toLocaleString()}</span>
                  <span className="text-right text-muted-foreground tabular-nums">{group.events.toLocaleString()}</span>
                  <span className="flex flex-wrap gap-1 text-[10px]">
                    {flagged.map(([verdict, count]) => (
                      <span key={verdict} className={cn("rounded border px-1.5 py-0.5", verdictTone[verdict])}>
                        {t(`cases.verdict.${verdict}`)} {count}
                      </span>
                    ))}
                    {group.unjudged > 0 && (
                      <span className="rounded border px-1.5 py-0.5 text-muted-foreground">
                        {t("cases.unjudged", { count: group.unjudged })}
                      </span>
                    )}
                  </span>
                  <span className="text-right text-[11px] text-muted-foreground tabular-nums">{stamp(group.last)}</span>
                </button>
              </div>

              {expanded && (
                // The group's cases, set apart from the group rows: indented,
                // with their own column names, each line opening the detail.
                <div className="border-t bg-muted/30 py-1.5 pr-3 pl-10">
                  <div className="overflow-hidden rounded-md border border-l-2 border-l-primary/50 bg-background">
                    <div className="flex items-center gap-2 border-b bg-muted/40 px-3 py-1.5 text-[11px] text-muted-foreground">
                      <span className="font-medium text-foreground">
                        {t("detections.casesIn", { count: group.cases.length })}
                      </span>
                      <span>{t("detections.casesHint")}</span>
                      {by === "host" && group.sourceId && (
                        <Link
                          href={hostDetailUrl(group.sourceId, `host:${group.label.split(".")[0].toLowerCase()}`)}
                          className="ml-auto flex items-center gap-1 hover:text-foreground [&_svg]:size-3"
                        >
                          {t("host.detail")}
                          <ArrowUpRightIcon />
                        </Link>
                      )}
                    </div>
                    <div className={cn(CASE_COLUMNS, "border-b px-3 py-1 text-[10px] text-muted-foreground")}>
                      <span>{t("detections.col.severity")}</span>
                      <span>{t(by === "rule" ? "detections.col.name.host" : "detections.col.case")}</span>
                      <span>{t(by === "rule" ? "detections.col.actor" : "detections.col.name.host")}</span>
                      <span className="text-right">{t("detections.col.events")}</span>
                      <span>{t("detections.col.state")}</span>
                      <span className="text-right">{t("detections.col.last")}</span>
                      <span />
                    </div>
                    {group.cases.slice(0, limit).map((c) => {
                      const key = caseKey(c);
                      const verdict = c.verdict;
                      const hosts = c.hosts.join(", ");
                      const title = verdict?.title ?? c.title ?? c.criterion;
                      return (
                        <button
                          key={key}
                          type="button"
                          onClick={() => onSelect(c)}
                          aria-pressed={selected === key}
                          className={cn(
                            CASE_COLUMNS,
                            "w-full border-b px-3 py-1.5 text-left last:border-b-0 hover:bg-muted",
                            selected === key && "bg-primary/10 hover:bg-primary/10",
                            isCleared(c) && "opacity-60",
                          )}
                        >
                          <span>
                            <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", severityTone[c.severity])}>
                              {t(`cases.severity.${c.severity}`)}
                            </span>
                          </span>
                          <span className="truncate font-medium" title={by === "rule" ? hosts : title}>
                            {by === "rule" ? hosts : title}
                          </span>
                          <span className="truncate text-muted-foreground" title={by === "rule" ? c.actor : hosts}>
                            {by === "rule" ? c.actor : hosts}
                          </span>
                          <span className="text-right text-muted-foreground tabular-nums">{c.n.toLocaleString()}</span>
                          <span className="text-[10px]">
                            {c.known ? (
                              <span className="text-muted-foreground">{t("cases.known")}</span>
                            ) : verdict ? (
                              <span
                                className={cn(
                                  "rounded border px-1.5 py-0.5",
                                  verdictTone[verdict.verdict],
                                  verdict.stale && "opacity-50",
                                )}
                              >
                                {t(`cases.verdict.${verdict.verdict}`)}
                              </span>
                            ) : (
                              <span className="text-muted-foreground">{t("detections.notJudged")}</span>
                            )}
                          </span>
                          <span className="text-right text-[11px] text-muted-foreground tabular-nums">
                            {stamp(c.last)}
                          </span>
                          <ChevronRightIcon
                            className={cn("size-3.5 text-muted-foreground", selected === key && "text-primary")}
                          />
                        </button>
                      );
                    })}
                  </div>
                  {group.cases.length > limit && (
                    <button
                      type="button"
                      className={moreButton}
                      onClick={() => setCaseLimit((prev) => ({ ...prev, [group.key]: limit + CASE_PAGE * 5 }))}
                    >
                      {t("detections.more", { count: group.cases.length - limit })}
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {groups.length > groupLimit && (
          <button type="button" className={moreButton} onClick={() => setGroupLimit((n) => n + GROUP_PAGE)}>
            {t("detections.more", { count: groups.length - groupLimit })}
          </button>
        )}
      </div>
    </div>
  );
}
