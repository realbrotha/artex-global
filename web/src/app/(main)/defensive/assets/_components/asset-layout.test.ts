import { describe, expect, it } from "vitest";

import type { AssetEdge, AssetNode } from "@/lib/wazuh-api";

import { layoutAssets, NODE_H, NODE_W, type Placement } from "./asset-layout";

const host = (id: string, kind: AssetNode["kind"] = "baremetal"): AssetNode => ({ id, kind, name: id });
const cluster = (id: string): AssetNode => ({ id, kind: "k8s_cluster", name: id });

const rect = (p: Placement) => ({ x: p.x, y: p.y, w: p.w ?? NODE_W, h: p.h ?? NODE_H });
const overlaps = (a: Placement, b: Placement) => {
  const r = rect(a);
  const s = rect(b);
  return r.x < s.x + s.w && s.x < r.x + r.w && r.y < s.y + s.h && s.y < r.y + r.h;
};
const inside = (inner: Placement, outer: Placement) => {
  const r = rect(inner);
  const s = rect(outer);
  return r.x >= s.x && r.y >= s.y && r.x + r.w <= s.x + s.w && r.y + r.h <= s.y + s.h;
};

function sample() {
  const nodes: AssetNode[] = [cluster("k8s-a"), cluster("k8s-b"), { id: "os", kind: "openstack", name: "os" }];
  const edges: AssetEdge[] = [];
  nodes.push(host("hv1"), host("hv2"));
  edges.push({ from: "hv1", to: "os", kind: "member_of" }, { from: "hv2", to: "os", kind: "member_of" });
  for (let i = 0; i < 9; i++) {
    nodes.push(host(`a${i}`, "vm"));
    edges.push({ from: `a${i}`, to: "k8s-a", kind: "member_of" });
    if (i < 4) edges.push({ from: `a${i}`, to: "hv1", kind: "runs_on" });
  }
  for (let i = 0; i < 2; i++) {
    nodes.push(host(`b${i}`, "vm"));
    edges.push({ from: `b${i}`, to: "k8s-b", kind: "member_of" });
  }
  nodes.push(host("bao1", "vm"), host("bao2", "vm"), host("mystery", "unknown"));
  edges.push({ from: "bao1", to: "hv2", kind: "runs_on" });
  return { nodes, edges };
}

describe("layoutAssets", () => {
  it("places every node and gives only cluster boxes a size", () => {
    const { nodes, edges } = sample();
    const pos = layoutAssets(nodes, edges);
    expect(pos.size).toBe(nodes.length);
    for (const n of nodes) {
      const p = pos.get(n.id);
      expect(p).toBeDefined();
      expect(Boolean(p?.w && p?.h)).toBe(n.kind === "k8s_cluster");
    }
  });

  it("draws each cluster as a box that contains exactly its own nodes", () => {
    const { nodes, edges } = sample();
    const pos = layoutAssets(nodes, edges);
    const at = (id: string) => pos.get(id) as Placement;
    for (let i = 0; i < 9; i++) expect(inside(at(`a${i}`), at("k8s-a"))).toBe(true);
    for (let i = 0; i < 2; i++) expect(inside(at(`b${i}`), at("k8s-b"))).toBe(true);
    for (const outsider of ["hv1", "hv2", "bao1", "bao2", "mystery", "os", "b0"]) {
      expect(overlaps(at(outsider), at("k8s-a"))).toBe(false);
    }
    expect(overlaps(at("k8s-a"), at("k8s-b"))).toBe(false);
  });

  it("puts physical hosts below everything that runs on them, and OpenStack below those", () => {
    const { nodes, edges } = sample();
    const pos = layoutAssets(nodes, edges);
    const at = (id: string) => pos.get(id) as Placement;
    const boxBottom = Math.max(...["k8s-a", "k8s-b"].map((id) => at(id).y + (at(id).h ?? 0)));
    for (const hv of ["hv1", "hv2"]) {
      expect(at(hv).y).toBeGreaterThan(boxBottom);
      expect(at(hv).y).toBeGreaterThan(at("bao1").y + NODE_H);
    }
    expect(at("hv1").y).toBe(at("hv2").y);
    expect(at("os").y).toBeGreaterThan(at("hv1").y + NODE_H);
  });

  it("never overlaps two hosts, including when boxes wrap onto new lines", () => {
    const nodes: AssetNode[] = [];
    const edges: AssetEdge[] = [];
    for (let c = 0; c < 9; c++) {
      nodes.push(cluster(`k${c}`));
      for (let m = 0; m < 2 + c; m++) {
        nodes.push(host(`k${c}-n${m}`, "vm"));
        edges.push({ from: `k${c}-n${m}`, to: `k${c}`, kind: "member_of" });
      }
    }
    for (let s = 0; s < 7; s++) nodes.push(host(`solo${s}`, "unknown"));
    for (let b = 0; b < 5; b++) nodes.push(host(`bm${b}`));
    const pos = layoutAssets(nodes, edges);
    const hosts = nodes.filter((n) => n.kind !== "k8s_cluster").map((n) => pos.get(n.id) as Placement);
    const boxes = nodes.filter((n) => n.kind === "k8s_cluster").map((n) => pos.get(n.id) as Placement);
    expect(new Set(boxes.map((b) => b.y)).size).toBeGreaterThan(1);
    for (let i = 0; i < hosts.length; i++) {
      for (let j = i + 1; j < hosts.length; j++) expect(overlaps(hosts[i], hosts[j])).toBe(false);
    }
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) expect(overlaps(boxes[i], boxes[j])).toBe(false);
    }
  });

  it("handles a map with no clusters", () => {
    const pos = layoutAssets([host("only")], []);
    expect(pos.get("only")).toEqual({ x: 0, y: 0 });
  });
});
