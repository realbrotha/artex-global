import type { AssetSource, CaseSeverity } from "@/lib/wazuh-api";

import { isCleared, type ListedCase, needsVerdict } from "./case-list";

export const SEVERITIES: CaseSeverity[] = ["Critical", "High", "Medium", "Low", "Info"];
const rankOf = (severity: CaseSeverity) => SEVERITIES.indexOf(severity);

// What one row of the grouped table stands for.
//   rule    - one detection criterion, across every host it fired on
//   host    - one host, across every criterion
//   cluster - one Kubernetes cluster (hosts outside any cluster share a row)
export const GROUP_BYS = ["rule", "host", "cluster"] as const;
export type GroupBy = (typeof GROUP_BYS)[number];

// How the group rows are ordered.
//   risk  - most severe open case first, then how many are open (default)
//   count - most cases first
//   name  - label, A to Z
export const GROUP_SORTS = ["risk", "count", "name"] as const;
export type GroupSort = (typeof GROUP_SORTS)[number];

// Cluster name of a host, "" when it belongs to none.
export type ClusterOf = (sourceId: string, host: string) => string;

const shortHost = (host: string) => host.split(".")[0].toLowerCase();

// Cases carry FQDNs and the asset graph short lowercase names; member_of
// edges say which cluster a host is in.
export function clusterLookup(sources: AssetSource[]): ClusterOf {
  const byHost = new Map<string, string>();
  for (const s of sources) {
    const names = new Map(s.nodes.map((n) => [n.id, n.name]));
    for (const e of s.edges) {
      if (e.kind !== "member_of") continue;
      byHost.set(`${s.id}/${e.from.replace(/^host:/, "")}`, names.get(e.to) ?? e.to);
    }
  }
  return (sourceId, host) => byHost.get(`${sourceId}/${shortHost(host)}`) ?? "";
}

export interface CaseGroup {
  key: string;
  by: GroupBy;
  // Criterion id, host name or cluster name ("" = no cluster).
  label: string;
  // Rule groups only: the criterion's readable title.
  title?: string;
  // Host groups only, for the link to the host page.
  sourceId?: string;
  cases: ListedCase[];
  // Cases someone may still need to act on, and the most severe of them.
  live: number;
  worst: CaseSeverity;
  unjudged: number;
  hosts: number;
  events: number;
  last: string;
}

// Hosts the cases involve, counted per connection.
export function countHosts(cases: ListedCase[]): number {
  return new Set(cases.flatMap((c) => c.hosts.map((h) => `${c.sourceId}/${h}`))).size;
}

function keysOf(c: ListedCase, by: GroupBy, clusterOf: ClusterOf): { key: string; label: string }[] {
  if (by === "rule") return [{ key: c.criterion, label: c.criterion }];
  if (by === "host") return c.hosts.map((h) => ({ key: `${c.sourceId}/${h}`, label: h }));
  const clusters = new Set(c.hosts.map((h) => clusterOf(c.sourceId, h)));
  return [...clusters].map((name) => ({ key: name, label: name }));
}

// One group per criterion, host or cluster. A case that spans several hosts
// or clusters is listed under each, so group counts can add up to more than
// the total.
export function groupCases(
  cases: ListedCase[],
  by: GroupBy,
  clusterOf: ClusterOf,
  sort: GroupSort = "risk",
): CaseGroup[] {
  const groups = new Map<string, CaseGroup>();
  for (const c of cases) {
    for (const { key, label } of keysOf(c, by, clusterOf)) {
      let group = groups.get(key);
      if (!group) {
        group = { key, by, label, cases: [], live: 0, worst: "Info", unjudged: 0, hosts: 0, events: 0, last: c.last };
        if (by === "rule") group.title = c.title;
        if (by === "host") group.sourceId = c.sourceId;
        groups.set(key, group);
      }
      group.cases.push(c);
      group.events += c.n;
      if (c.last > group.last) group.last = c.last;
      if (needsVerdict(c)) group.unjudged += 1;
      if (!isCleared(c)) {
        group.live += 1;
        if (rankOf(c.severity) < rankOf(group.worst)) group.worst = c.severity;
      }
    }
  }
  for (const group of groups.values()) group.hosts = countHosts(group.cases);

  const byName = (a: CaseGroup, b: CaseGroup) =>
    Number(a.label === "") - Number(b.label === "") || a.label.localeCompare(b.label, undefined, { numeric: true });
  const byRisk = (a: CaseGroup, b: CaseGroup) =>
    Number(b.live > 0) - Number(a.live > 0) || rankOf(a.worst) - rankOf(b.worst) || b.live - a.live;
  const order: Record<GroupSort, (a: CaseGroup, b: CaseGroup) => number> = {
    risk: (a, b) => byRisk(a, b) || b.events - a.events || byName(a, b),
    count: (a, b) => b.cases.length - a.cases.length || byRisk(a, b) || byName(a, b),
    name: byName,
  };
  return [...groups.values()].sort(order[sort]);
}

export type SeverityCounts = Record<CaseSeverity, number>;
const noCounts = (): SeverityCounts => ({ Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 });

export interface Timeline {
  // Cases that began in each time bucket, by severity.
  buckets: SeverityCounts[];
  // Tallest bucket, for the bar scale.
  max: number;
  start: number;
  bucketMs: number;
}

// When the cases began: each counts once, in the bucket of its first alert.
// A case that began before the window counts in the first bucket.
export function timeline(cases: ListedCase[], start: number, end: number, columns: number): Timeline {
  const bucketMs = Math.max(1, (end - start) / columns);
  const buckets = Array.from({ length: columns }, noCounts);
  const totals = new Array<number>(columns).fill(0);
  for (const c of cases) {
    const at = Math.floor((Date.parse(c.first) - start) / bucketMs);
    if (Number.isNaN(at) || at > columns - 1) continue;
    const index = Math.max(0, at);
    buckets[index][c.severity] += 1;
    totals[index] += 1;
  }
  return { buckets, max: Math.max(0, ...totals), start, bucketMs };
}

export interface ClusterCount {
  cluster: string;
  total: number;
  severities: SeverityCounts;
}

// Cases per cluster by severity, largest first. A case whose hosts span
// clusters counts under each.
export function clusterCounts(cases: ListedCase[], clusterOf: ClusterOf): ClusterCount[] {
  const rows = new Map<string, ClusterCount>();
  for (const c of cases) {
    for (const cluster of new Set(c.hosts.map((h) => clusterOf(c.sourceId, h)))) {
      let row = rows.get(cluster);
      if (!row) {
        row = { cluster, total: 0, severities: noCounts() };
        rows.set(cluster, row);
      }
      row.total += 1;
      row.severities[c.severity] += 1;
    }
  }
  return [...rows.values()].sort((x, y) => y.total - x.total || x.cluster.localeCompare(y.cluster));
}

export interface RuleCount {
  criterion: string;
  title?: string;
  cases: number;
  hosts: number;
  worst: CaseSeverity;
}

// The criteria with the most cases.
export function topRules(cases: ListedCase[], limit: number): RuleCount[] {
  return groupCases(cases, "rule", () => "", "count")
    .slice(0, limit)
    .map((g) => ({ criterion: g.label, title: g.title, cases: g.cases.length, hosts: g.hosts, worst: g.worst }));
}

// Narrowing chosen on the overview: a quick filter from the tiles, a
// criterion from the ranking, a cluster, and the time range the case began in.
export interface CaseFilter {
  quick?: "severe" | "unjudged";
  criterion?: string;
  // "" selects hosts outside any cluster.
  cluster?: string;
  from?: number;
  to?: number;
  // The first bar of the timeline: it also holds cases that began before
  // the window, so "from" is not a lower bound.
  earlier?: boolean;
}

export function matchesFilter(c: ListedCase, f: CaseFilter, clusterOf: ClusterOf): boolean {
  if (f.quick === "severe" && c.severity !== "Critical" && c.severity !== "High") return false;
  if (f.quick === "unjudged" && !needsVerdict(c)) return false;
  if (f.criterion !== undefined && c.criterion !== f.criterion) return false;
  if (f.cluster !== undefined && !c.hosts.some((h) => clusterOf(c.sourceId, h) === f.cluster)) return false;
  if (f.from !== undefined && !f.earlier && Date.parse(c.first) < f.from) return false;
  if (f.to !== undefined && Date.parse(c.first) >= f.to) return false;
  return true;
}
