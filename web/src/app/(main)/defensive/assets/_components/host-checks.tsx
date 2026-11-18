"use client";

import * as React from "react";

import { ChevronRightIcon, SearchIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { type AssetChecks, type AssetIssue, wazuhApi } from "@/lib/wazuh-api";

// What the issue list shows: one result, or everything the registry accepts.
type View = AssetIssue["result"] | "accepted";

const viewTone: Record<View, string> = {
  fail: "text-danger",
  review: "text-info",
  error: "text-warning",
  accepted: "text-primary",
};

const sevRank: Record<string, number> = { 상: 0, 중: 1, 하: 2 };
const stdOrder = ["kisa", "cis", "siem"];

// One check code, possibly reported for several services or containers.
interface IssueGroup {
  key: string;
  code: string;
  sev?: string;
  title?: string;
  rows: AssetIssue[];
}

const inView = (issue: AssetIssue, view: View) =>
  view === "accepted" ? Boolean(issue.accepted) : issue.result === view && !issue.accepted;

function groupIssues(issues: AssetIssue[], view: View, std: string, query: string) {
  const q = query.trim().toLowerCase();
  const byStd = new Map<string, Map<string, IssueGroup>>();
  for (const issue of issues) {
    if (!inView(issue, view)) continue;
    // std is omitted (never empty) when the record has none.
    const issueStd = issue.std ?? "etc";
    if (std !== "all" && issueStd !== std) continue;
    if (q && ![issue.code, issue.key, issue.title, issue.ev, issue.asset].some((v) => v?.toLowerCase().includes(q)))
      continue;
    const code = issue.key ?? issue.code;
    const groups = byStd.get(issueStd) ?? new Map<string, IssueGroup>();
    byStd.set(issueStd, groups);
    const group = groups.get(code) ?? {
      key: `${issueStd}:${code}`,
      code,
      sev: issue.sev,
      title: issue.title,
      rows: [],
    };
    groups.set(code, group);
    group.rows.push(issue);
  }
  const stdRank = (s: string) => (stdOrder.includes(s) ? stdOrder.indexOf(s) : stdOrder.length);
  return [...byStd.entries()]
    .sort(([a], [b]) => stdRank(a) - stdRank(b) || a.localeCompare(b))
    .map(([std, groups]) => ({
      std,
      groups: [...groups.values()].sort(
        (a, b) =>
          (sevRank[a.sev ?? ""] ?? 3) - (sevRank[b.sev ?? ""] ?? 3) ||
          a.code.localeCompare(b.code, undefined, { numeric: true }),
      ),
    }));
}

const firstView = (checks: AssetChecks): View =>
  checks.fail > 0 ? "fail" : checks.error > 0 ? "error" : checks.review > 0 ? "review" : "accepted";

interface CheckTilesProps {
  readonly checks: AssetChecks;
  // With onSelect the tiles act as a filter; without it they only show counts.
  readonly view?: View;
  readonly onSelect?: (view: View) => void;
}

// Result counts of one host's latest config check.
export function CheckTiles({ checks, view, onSelect }: CheckTilesProps) {
  const t = useTranslations("protectedAssets.checks");
  const tiles: { key: View | "pass"; value: number }[] = [
    { key: "fail", value: checks.fail },
    { key: "review", value: checks.review },
    { key: "error", value: checks.error },
    { key: "accepted", value: checks.accepted ?? 0 },
    { key: "pass", value: checks.pass },
  ];
  return (
    <div className="grid grid-cols-5 gap-1">
      {tiles.map((tile) => {
        const selectable = Boolean(onSelect) && tile.key !== "pass" && tile.value > 0;
        return (
          <button
            key={tile.key}
            type="button"
            disabled={!selectable}
            onClick={() => selectable && onSelect?.(tile.key as View)}
            className={cn(
              "rounded border px-0.5 py-1 text-center",
              selectable && "hover:bg-muted/60",
              tile.key === view && "border-primary bg-primary/5",
            )}
          >
            <div
              className={cn(
                "font-semibold text-sm tabular-nums",
                tile.value > 0 && (tile.key === "pass" ? "text-success" : viewTone[tile.key as View]),
              )}
            >
              {tile.value}
            </div>
            <div className="truncate text-[10px] text-muted-foreground">{t(`result.${tile.key}`)}</div>
          </button>
        );
      })}
    </div>
  );
}

interface HostChecksProps {
  readonly sourceId: string;
  // Node id as the connection reports it (without the connection prefix).
  readonly nodeId: string;
  readonly checks: AssetChecks;
}

// Config-check results of one host at full width: filter by result, standard
// and text; one row per check code, expanding to evidence per target.
export function HostChecks({ sourceId, nodeId, checks }: HostChecksProps) {
  const t = useTranslations("protectedAssets.checks");
  const [issues, setIssues] = React.useState<AssetIssue[] | null>(null);
  const [error, setError] = React.useState("");
  const [open, setOpen] = React.useState<string | null>(null);
  const [view, setView] = React.useState<View>(() => firstView(checks));
  const [std, setStd] = React.useState("all");
  const [query, setQuery] = React.useState("");

  React.useEffect(() => {
    let live = true;
    wazuhApi
      .checks(sourceId, nodeId)
      .then((r) => {
        if (live) setIssues(r.issues);
      })
      .catch((e: unknown) => {
        if (live) setError(e instanceof Error ? e.message : t("loadFailed"));
      });
    return () => {
      live = false;
    };
  }, [sourceId, nodeId, t]);

  const stds = React.useMemo(() => {
    const found = [...new Set((issues ?? []).filter((i) => inView(i, view)).map((i) => i.std ?? "etc"))];
    return found.sort((a, b) => stdOrder.indexOf(a) - stdOrder.indexOf(b));
  }, [issues, view]);
  const sections = React.useMemo(
    () => (issues ? groupIssues(issues, view, std, query) : []),
    [issues, view, std, query],
  );
  const stdLabel = (s: string) => (t.has(`std.${s}`) ? t(`std.${s}`) : s);

  return (
    <div className="grid grid-cols-1 gap-3">
      <div className="max-w-md">
        <CheckTiles
          checks={checks}
          view={view}
          onSelect={(next) => {
            setView(next);
            setStd("all");
            setOpen(null);
          }}
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {["all", ...stds].map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setStd(s)}
            className={cn(
              "rounded-md border px-2.5 py-1 text-xs",
              std === s ? "border-primary bg-primary/5" : "hover:bg-muted/50",
            )}
          >
            {s === "all" ? t("filterAll") : stdLabel(s)}
          </button>
        ))}
        <div className="relative ml-auto w-full sm:w-72">
          <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("searchPlaceholder")}
            className="pl-8"
          />
        </div>
      </div>
      <p className="text-[11px] text-muted-foreground">{t("rawNote")}</p>
      {error && <p className="text-destructive text-sm">{error}</p>}
      {issues === null && !error && <Skeleton className="h-40 w-full" />}
      {issues !== null && sections.length === 0 && (
        <p className="rounded-lg border border-dashed p-8 text-center text-muted-foreground text-sm">
          {issues.length === 0 ? t("noIssues") : t("noMatch")}
        </p>
      )}
      {sections.map((section) => (
        <section key={section.std} className="grid grid-cols-1 gap-1.5">
          <h3 className="flex items-baseline gap-2 font-medium text-sm">
            {stdLabel(section.std)}
            <span className="font-normal text-muted-foreground text-xs tabular-nums">
              {t("codeCount", { count: section.groups.length })}
            </span>
          </h3>
          <ul className="grid grid-cols-1 divide-y rounded-lg border text-sm">
            {section.groups.map((group) => {
              const expanded = open === group.key;
              const acceptance = group.rows.find((row) => row.accepted)?.accepted;
              return (
                <li key={group.key}>
                  <button
                    type="button"
                    onClick={() => setOpen(expanded ? null : group.key)}
                    aria-expanded={expanded}
                    className="grid w-full grid-cols-[auto_7rem_2rem_minmax(0,1fr)_auto] items-baseline gap-x-3 px-3 py-2 text-left hover:bg-muted/60"
                  >
                    <ChevronRightIcon
                      className={cn(
                        "size-3.5 self-center text-muted-foreground transition-transform",
                        expanded && "rotate-90",
                      )}
                    />
                    <span className="truncate font-mono text-xs">{group.code}</span>
                    <span className="text-muted-foreground text-xs">{group.sev}</span>
                    <span className={cn("min-w-0 break-words", !expanded && "truncate")}>{group.title}</span>
                    <span className="text-muted-foreground text-xs tabular-nums">
                      {group.rows.length > 1 && t("targetCount", { count: group.rows.length })}
                    </span>
                  </button>
                  {expanded && (
                    <div className="grid grid-cols-1 gap-2 border-t bg-muted/20 px-3 py-2.5 text-xs">
                      {acceptance && (
                        <div className="grid grid-cols-1 gap-0.5 rounded bg-primary/10 p-2">
                          <p className="font-medium text-primary">
                            {t("acceptedBy", {
                              who: acceptance.approved_by,
                              until: acceptance.until || t("noExpiry"),
                            })}
                            {acceptance.host === "*" && ` · ${t("allHosts")}`}
                          </p>
                          <p className="break-words">{acceptance.reason}</p>
                        </div>
                      )}
                      {group.rows.map((row, index) => (
                        <div key={`${row.asset ?? ""}:${index}`} className="grid grid-cols-1 gap-1">
                          {row.asset && (
                            <p className="break-all text-muted-foreground">
                              {t("target")}: {row.asset}
                            </p>
                          )}
                          {row.ev ? (
                            <pre className="whitespace-pre-wrap break-all rounded bg-muted/60 p-2 font-mono leading-snug">
                              {row.ev}
                            </pre>
                          ) : (
                            <p className="text-muted-foreground">{t("noEvidence")}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </div>
  );
}
