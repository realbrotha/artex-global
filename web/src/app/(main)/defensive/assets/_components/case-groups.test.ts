import { describe, expect, it } from "vitest";

import type { AssetSource, CaseSeverity } from "@/lib/wazuh-api";

import { clusterCounts, clusterLookup, groupCases, matchesFilter, timeline, topRules } from "./case-groups";
import type { ListedCase } from "./case-list";

const item = (id: string, hosts: string[], severity: CaseSeverity, extra: Partial<ListedCase> = {}): ListedCase => ({
  id,
  sourceId: "1",
  sourceName: "wazuh",
  pattern: "P9",
  score: 10,
  entity: "",
  hosts,
  first: "2026-11-10T00:00:00Z",
  last: "2026-11-11T00:00:00Z",
  n: 1,
  attack: [],
  summary: "",
  near: [],
  severity,
  sev_basis: "",
  criterion: "EV-TEST",
  actor: "",
  ...extra,
});

const normal = {
  verdict: "normal" as const,
  title: "",
  explain: "",
  evidence: [],
  severity: "Low" as const,
  model: "",
  judged_at: "2026-11-11T00:00:00Z",
  stale: false,
};

const none = () => "";
const groupCasesByHost = (cases: ListedCase[], sort?: "risk" | "count" | "name") =>
  groupCases(cases, "host", none, sort);

describe("groupCases by host", () => {
  it("lists a case under every host it names", () => {
    const groups = groupCasesByHost([item("a", ["web01", "db01"], "High"), item("b", ["web01"], "Low")]);
    expect(groups.map((g) => [g.label, g.cases.map((c) => c.id)])).toEqual([
      ["web01", ["a", "b"]],
      ["db01", ["a"]],
    ]);
  });

  it("puts the host with the most severe open case first", () => {
    const groups = groupCasesByHost([
      item("a", ["many-low"], "Low"),
      item("b", ["many-low"], "Low"),
      item("c", ["one-critical"], "Critical"),
      item("d", ["medium"], "Medium"),
    ]);
    expect(groups.map((g) => g.label)).toEqual(["one-critical", "medium", "many-low"]);
    expect(groups[0]).toMatchObject({ worst: "Critical", live: 1 });
  });

  it("ranks a host by its open cases, not by ones judged normal or known", () => {
    const groups = groupCasesByHost([
      item("a", ["quiet"], "Critical", { verdict: normal }),
      item("b", ["quiet"], "High", { known: "scheduled backup" }),
      item("c", ["busy"], "Low"),
    ]);
    expect(groups.map((g) => g.label)).toEqual(["busy", "quiet"]);
    expect(groups[1]).toMatchObject({ live: 0, worst: "Info" });
    // The cleared cases are still listed under the host.
    expect(groups[1].cases).toHaveLength(2);
  });

  it("keeps the same host name apart across connections", () => {
    const groups = groupCasesByHost([item("a", ["web01"], "Low"), item("b", ["web01"], "Low", { sourceId: "2" })]);
    expect(groups).toHaveLength(2);
  });

  it("sorts by name or by case count on request", () => {
    const cases = [
      item("a", ["web10"], "Low"),
      item("b", ["web2"], "Critical"),
      item("c", ["db01"], "Low"),
      item("d", ["db01"], "Low"),
      item("e", ["db01"], "Low", { verdict: normal }),
    ];
    // Default: the host with the critical case leads.
    expect(groupCasesByHost(cases).map((g) => g.label)).toEqual(["web2", "db01", "web10"]);
    // Numbers in names sort as numbers: web2 before web10.
    expect(groupCasesByHost(cases, "name").map((g) => g.label)).toEqual(["db01", "web2", "web10"]);
    // Every listed case counts, cleared ones included; ties fall back to risk.
    expect(groupCasesByHost(cases, "count").map((g) => g.label)).toEqual(["db01", "web2", "web10"]);
  });
});

const assets: AssetSource[] = [
  {
    id: "1",
    name: "wazuh",
    synced_at: null,
    sync_error: "",
    indexer: true,
    nodes: [
      { id: "k8s:aaa", kind: "k8s_cluster", name: "Kubernetes aaa" },
      { id: "host:cp01", kind: "vm", name: "cp01" },
      { id: "host:web01", kind: "vm", name: "web01" },
    ],
    edges: [{ from: "host:cp01", to: "k8s:aaa", kind: "member_of" }],
  },
];

describe("groupCases by rule and cluster", () => {
  const clusterOf = clusterLookup(assets);

  it("resolves a case's FQDN to the host's cluster", () => {
    expect(clusterOf("1", "CP01.example.internal")).toBe("Kubernetes aaa");
    expect(clusterOf("1", "web01")).toBe("");
    expect(clusterOf("2", "cp01")).toBe("");
  });

  it("folds one criterion on many hosts into one row", () => {
    const groups = groupCases(
      [
        item("a", ["web01"], "High", { n: 5, title: "SSH brute force" }),
        item("b", ["cp01"], "Critical", { n: 7 }),
        item("c", ["web01"], "Low", { criterion: "EV-OTHER" }),
      ],
      "rule",
      clusterOf,
    );
    expect(groups.map((g) => g.label)).toEqual(["EV-TEST", "EV-OTHER"]);
    expect(groups[0]).toMatchObject({ title: "SSH brute force", hosts: 2, events: 12, worst: "Critical", unjudged: 2 });
  });

  it("groups by cluster with unclustered hosts last by name", () => {
    const groups = groupCases(
      [item("a", ["web01"], "Low"), item("b", ["cp01", "web01"], "Low")],
      "cluster",
      clusterOf,
      "name",
    );
    expect(groups.map((g) => [g.label, g.cases.length])).toEqual([
      ["Kubernetes aaa", 1],
      ["", 2],
    ]);
  });
});

describe("overview", () => {
  const clusterOf = clusterLookup(assets);
  const day = 86_400_000;
  const start = Date.parse("2026-11-10T00:00:00Z");
  const cases = [
    item("a", ["cp01"], "High"),
    item("b", ["web01"], "Low", { first: "2026-11-12T06:00:00Z", last: "2026-11-12T07:00:00Z", criterion: "EV-OTHER" }),
    item("c", ["web01"], "Low", { first: "2026-11-01T00:00:00Z", last: "2026-11-02T00:00:00Z" }),
  ];

  it("counts a case once, in the bucket it began in", () => {
    const line = timeline(cases, start, start + 4 * day, 4);
    expect(line.buckets.map((b) => [b.High, b.Low])).toEqual([
      [1, 1], // "c" began before the window
      [0, 0],
      [0, 1],
      [0, 0],
    ]);
    expect(line.max).toBe(2);
  });

  it("counts cases per cluster by severity", () => {
    expect(clusterCounts(cases, clusterOf).map((r) => [r.cluster, r.total, r.severities.Low])).toEqual([
      ["", 2, 2],
      ["Kubernetes aaa", 1, 0],
    ]);
  });

  it("ranks criteria by case count", () => {
    expect(topRules(cases, 1)).toEqual([{ criterion: "EV-TEST", title: undefined, cases: 2, hosts: 2, worst: "High" }]);
  });

  it("narrows by tile, criterion, cluster and time range", () => {
    const ids = (f: Parameters<typeof matchesFilter>[1]) =>
      cases.filter((c) => matchesFilter(c, f, clusterOf)).map((c) => c.id);
    expect(ids({ quick: "severe" })).toEqual(["a"]);
    expect(ids({ criterion: "EV-OTHER" })).toEqual(["b"]);
    expect(ids({ cluster: "" })).toEqual(["b", "c"]);
    expect(ids({ from: start + 2 * day, to: start + 3 * day })).toEqual(["b"]);
    expect(ids({ from: start, to: start + day })).toEqual(["a"]);
    // The first bar also lists what began before the window.
    expect(ids({ from: start, to: start + day, earlier: true })).toEqual(["a", "c"]);
    expect(ids({ quick: "unjudged" })).toEqual(["a", "b", "c"]);
  });
});
