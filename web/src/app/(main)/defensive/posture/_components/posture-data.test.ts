import { describe, expect, it } from "vitest";

import { matchesPosture, type Row, sevCounts, sortRows, stdCounts, topHosts } from "./posture-data";

const row = (code: string, sev: string, fail: string[], extra: Partial<Row> = {}): Row => ({
  code,
  std: "kisa",
  sev,
  title: code,
  fail,
  review: [],
  error: [],
  accepted: [],
  sourceId: "1",
  key: `1/kisa/${code}`,
  ...extra,
});

const rows = [
  row("U-10", "하", ["web01", "web02", "db01"]),
  row("U-2", "상", ["web01"]),
  row("CIS 1.1", "", ["db01", "web01"], { std: "cis" }),
  row("U-30", "중", ["web01"], { sourceId: "2" }),
];

describe("posture overview", () => {
  it("counts checks per grade, highest first", () => {
    expect(sevCounts(rows)).toEqual([
      { sev: "상", checks: 1 },
      { sev: "중", checks: 1 },
      { sev: "하", checks: 1 },
      { sev: "", checks: 1 },
    ]);
  });

  it("counts checks per standard", () => {
    expect(stdCounts(rows).map((s) => [s.std, s.checks])).toEqual([
      ["kisa", 3],
      ["cis", 1],
    ]);
  });

  it("ranks hosts by failing checks, apart per connection", () => {
    expect(topHosts(rows, "fail", 2).map((h) => [h.key, h.checks])).toEqual([
      ["1/web01", 3],
      ["1/db01", 2],
    ]);
  });
});

describe("posture table", () => {
  it("narrows by standard, grade and host", () => {
    const codes = (f: Parameters<typeof matchesPosture>[2]) =>
      rows.filter((r) => matchesPosture(r, "fail", f)).map((r) => r.code);
    expect(codes({ std: "cis" })).toEqual(["CIS 1.1"]);
    expect(codes({ sev: "" })).toEqual(["CIS 1.1"]);
    expect(codes({ host: "1/db01" })).toEqual(["U-10", "CIS 1.1"]);
    expect(codes({ host: "2/web01", sev: "중" })).toEqual(["U-30"]);
  });

  it("sorts by hosts, grade or code", () => {
    const codes = (sort: Parameters<typeof sortRows>[2]) => sortRows(rows, "fail", sort).map((r) => r.code);
    expect(codes("impact")).toEqual(["U-10", "CIS 1.1", "U-2", "U-30"]);
    expect(codes("severity")).toEqual(["U-2", "U-30", "U-10", "CIS 1.1"]);
    // Numbers in codes sort as numbers: U-2 before U-10.
    expect(codes("code")).toEqual(["CIS 1.1", "U-2", "U-10", "U-30"]);
  });
});
