import type { CheckSummary } from "@/lib/wazuh-api";

export const RESULTS = ["fail", "review", "error", "accepted"] as const;
export type Result = (typeof RESULTS)[number];

// One check of one connection.
export type Row = CheckSummary & { sourceId: string; key: string };

// Grades as config-check reports them, highest first; "" = not graded.
export const SEVS = ["상", "중", "하", ""] as const;
const sevRank = (sev?: string) => {
  const index = (SEVS as readonly string[]).indexOf(sev ?? "");
  return index < 0 ? SEVS.length : index;
};
export const stdOf = (row: CheckSummary) => row.std ?? "etc";
export const hostKey = (sourceId: string, host: string) => `${sourceId}/${host}`;

// Narrowing chosen on the overview. host is a hostKey.
export interface PostureFilter {
  std?: string;
  sev?: string;
  host?: string;
}

export function matchesPosture(row: Row, result: Result, f: PostureFilter): boolean {
  if (f.std !== undefined && stdOf(row) !== f.std) return false;
  if (f.sev !== undefined && (row.sev ?? "") !== f.sev) return false;
  if (f.host !== undefined && !row[result].some((h) => hostKey(row.sourceId, h) === f.host)) return false;
  return true;
}

export interface SevCount {
  sev: string;
  checks: number;
}

// Checks per grade, highest grade first; grades with none are left out.
export function sevCounts(rows: Row[]): SevCount[] {
  const counts = new Map<string, number>();
  for (const row of rows) counts.set(row.sev ?? "", (counts.get(row.sev ?? "") ?? 0) + 1);
  return [...counts].map(([sev, checks]) => ({ sev, checks })).sort((a, b) => sevRank(a.sev) - sevRank(b.sev));
}

export interface StdCount {
  std: string;
  checks: number;
  // Checks per grade, for the stacked bar.
  sevs: SevCount[];
}

// Checks per standard, in the order the server lists them (KISA, CIS, own).
export function stdCounts(rows: Row[]): StdCount[] {
  const groups = new Map<string, Row[]>();
  for (const row of rows) groups.set(stdOf(row), [...(groups.get(stdOf(row)) ?? []), row]);
  return [...groups].map(([std, list]) => ({ std, checks: list.length, sevs: sevCounts(list) }));
}

export interface HostCount {
  key: string;
  sourceId: string;
  host: string;
  checks: number;
}

// The hosts with the most checks in this result.
export function topHosts(rows: Row[], result: Result, limit: number): HostCount[] {
  const counts = new Map<string, HostCount>();
  for (const row of rows) {
    for (const host of row[result]) {
      const key = hostKey(row.sourceId, host);
      const entry = counts.get(key) ?? { key, sourceId: row.sourceId, host, checks: 0 };
      entry.checks += 1;
      counts.set(key, entry);
    }
  }
  return [...counts.values()]
    .sort((a, b) => b.checks - a.checks || a.host.localeCompare(b.host, undefined, { numeric: true }))
    .slice(0, limit);
}

// How the check rows are ordered.
//   impact   - most hosts in the selected result first (default)
//   severity - highest grade first, then most hosts
//   code     - check code, A to Z
export const POSTURE_SORTS = ["impact", "severity", "code"] as const;
export type PostureSort = (typeof POSTURE_SORTS)[number];

export function sortRows(rows: Row[], result: Result, sort: PostureSort): Row[] {
  const byCode = (a: Row, b: Row) => a.code.localeCompare(b.code, undefined, { numeric: true });
  const byHosts = (a: Row, b: Row) => b[result].length - a[result].length;
  const bySev = (a: Row, b: Row) => sevRank(a.sev) - sevRank(b.sev);
  const order: Record<PostureSort, (a: Row, b: Row) => number> = {
    impact: (a, b) => byHosts(a, b) || bySev(a, b) || byCode(a, b),
    severity: (a, b) => bySev(a, b) || byHosts(a, b) || byCode(a, b),
    code: byCode,
  };
  return [...rows].sort(order[sort]);
}
