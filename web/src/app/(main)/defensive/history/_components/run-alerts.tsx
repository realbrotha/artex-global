"use client";

import * as React from "react";

import { ChevronRightIcon, SearchIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { type Analysis, historyApi, type RunAlert } from "@/lib/wazuh-api";

const PAGE = 100;
// The server stores at most this many alerts per run.
const STORED_MAX = 50000;
const COLUMNS =
  "grid grid-cols-[1rem_8rem_minmax(0,9rem)_4rem_2.5rem_minmax(0,2fr)_minmax(0,1fr)_minmax(0,7rem)] items-center gap-x-3";
const select = "h-8 max-w-64 rounded-md border bg-background px-2 text-xs";

const stampSeconds = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

interface RunAlertsProps {
  readonly runId: string;
  readonly detail: Analysis;
}

// The alerts a run collected, as it read them: filter by rule or host,
// search the text, open one for its raw log.
export function RunAlerts({ runId, detail }: RunAlertsProps) {
  const t = useTranslations("protectedAssets.history.alerts");
  const [rule, setRule] = React.useState("");
  const [host, setHost] = React.useState("");
  const [typed, setTyped] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [offset, setOffset] = React.useState(0);
  const [page, setPage] = React.useState<{ total: number; alerts: RunAlert[] } | "error" | null>(null);
  const [open, setOpen] = React.useState<number | null>(null);

  React.useEffect(() => {
    let alive = true;
    setPage(null);
    historyApi
      .alerts(runId, { rule, host, q: query, offset, limit: PAGE })
      .then((next) => alive && setPage(next))
      .catch(() => alive && setPage("error"));
    return () => {
      alive = false;
    };
  }, [runId, rule, host, query, offset]);

  const stored = detail.alerts_stored;
  if (stored === -1) return <p className="rounded-lg border border-dashed p-8 text-center text-sm">{t("storing")}</p>;
  if (!stored) {
    return <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">{t("none")}</p>;
  }

  const narrow = (apply: () => void) => {
    apply();
    setOffset(0);
    setOpen(null);
  };
  const total = page && page !== "error" ? page.total : 0;

  return (
    <div className="grid grid-cols-1 gap-2 text-xs">
      {detail.alerts > STORED_MAX && (
        <p className="text-amber-600 dark:text-amber-400">{t("capped", { max: STORED_MAX, total: detail.alerts })}</p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <select
          className={select}
          value={rule}
          onChange={(e) => narrow(() => setRule(e.target.value))}
          aria-label={t("col.rule")}
        >
          <option value="">{t("allRules")}</option>
          {detail.top_rules.map((r) => (
            <option key={r.id} value={r.id}>
              {r.id} · {r.desc.slice(0, 50)} ({r.count.toLocaleString()})
            </option>
          ))}
        </select>
        <select
          className={select}
          value={host}
          onChange={(e) => narrow(() => setHost(e.target.value))}
          aria-label={t("col.host")}
        >
          <option value="">{t("allHosts")}</option>
          {(detail.alert_by_host ?? []).map((h) => (
            <option key={h.host} value={h.host}>
              {h.host} ({h.count.toLocaleString()})
            </option>
          ))}
        </select>
        <form
          className="relative w-full sm:w-72"
          onSubmit={(e) => {
            e.preventDefault();
            narrow(() => setQuery(typed.trim()));
          }}
        >
          <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={t("search")}
            className="h-8 pl-8 text-xs"
          />
        </form>
        <span className="ml-auto flex items-center gap-2 text-muted-foreground tabular-nums">
          {total > 0 && t("page", { from: offset + 1, to: Math.min(offset + PAGE, total), total })}
          <Button size="xs" variant="outline" disabled={offset === 0} onClick={() => setOffset(offset - PAGE)}>
            {t("prev")}
          </Button>
          <Button
            size="xs"
            variant="outline"
            disabled={offset + PAGE >= total}
            onClick={() => setOffset(offset + PAGE)}
          >
            {t("next")}
          </Button>
        </span>
      </div>

      {page === null && <Skeleton className="h-64 w-full" />}
      {page === "error" && <p className="text-destructive">{t("loadFailed")}</p>}
      {page && page !== "error" && page.alerts.length === 0 && (
        <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">{t("noMatch")}</p>
      )}
      {page && page !== "error" && page.alerts.length > 0 && (
        <div className="overflow-x-auto rounded-lg border">
          <div className="min-w-[54rem]">
            <div className={cn(COLUMNS, "border-b bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground")}>
              <span />
              <span>{t("col.time")}</span>
              <span>{t("col.host")}</span>
              <span>{t("col.rule")}</span>
              <span>{t("col.level")}</span>
              <span>{t("col.desc")}</span>
              <span>{t("col.actor")}</span>
              <span>{t("col.src")}</span>
            </div>
            {page.alerts.map((a) => {
              const expanded = open === a.seq;
              return (
                <div key={a.seq} className="border-b last:border-b-0">
                  <button
                    type="button"
                    onClick={() => setOpen(expanded ? null : a.seq)}
                    aria-expanded={expanded}
                    className={cn(COLUMNS, "w-full px-3 py-1 text-left hover:bg-muted/50", expanded && "bg-muted/40")}
                  >
                    <ChevronRightIcon
                      className={cn("size-3 text-muted-foreground transition-transform", expanded && "rotate-90")}
                    />
                    <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
                      {stampSeconds(a.t)}
                    </span>
                    <span className="truncate" title={a.host}>
                      {a.host}
                    </span>
                    <span className="font-mono text-[11px]">{a.rule}</span>
                    <span className={cn("tabular-nums", a.level >= 10 && "font-medium text-red-600 dark:text-red-400")}>
                      {a.level}
                    </span>
                    <span className="truncate" title={a.desc}>
                      {a.desc}
                    </span>
                    <span className="truncate text-muted-foreground" title={a.actor}>
                      {a.actor !== "-" && a.actor}
                    </span>
                    <span className="truncate text-muted-foreground" title={a.src}>
                      {a.src !== "-" && a.src}
                    </span>
                  </button>
                  {expanded && (
                    <div className="grid grid-cols-1 gap-1.5 border-t bg-muted/10 p-3 pl-10">
                      <p className="break-words">{a.desc}</p>
                      {a.object && (
                        <p className="break-all">
                          <span className="text-muted-foreground">{t("object")}: </span>
                          <span className="font-mono text-[11px]">{a.object}</span>
                        </p>
                      )}
                      <p className="text-[11px] text-muted-foreground">{t("fullLog")}</p>
                      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted/40 p-2 font-mono text-[11px] leading-relaxed">
                        {a.full_log || t("noLog")}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
