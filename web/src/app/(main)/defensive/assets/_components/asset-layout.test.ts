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

describe("layoutByDepth", () => {
  it("places guests below their host and groups on top", async () => {
    const { layoutByDepth } = await import("./asset-layout");
    const { nodes, edges } = sample();
    const { pos, tiers } = layoutByDepth(nodes, edges);
    const y = (id: string) => pos.get(id)?.y ?? Number.NaN;
    expect(y("os")).toBeLessThan(y("hv1"));
    expect(y("hv1")).toBe(y("hv2"));
    for (const e of edges.filter((e) => e.kind === "runs_on")) expect(y(e.from)).toBeGreaterThan(y(e.to));
    // A VM with no known hypervisor is still a guest, not a physical host.
    const orphan = nodes.find((n) => n.kind === "vm" && !edges.some((e) => e.kind === "runs_on" && e.from === n.id));
    if (orphan) expect(y(orphan.id)).toBeGreaterThan(y("hv1"));
    expect(tiers.map((t) => t.depth)).toEqual([...tiers.map((t) => t.depth)].sort((a, b) => a - b));
    expect(tiers[0].depth).toBe(-1);
  });

  it("places every node without overlap and keeps members in their box", async () => {
    const { layoutByDepth } = await import("./asset-layout");
    const { nodes, edges } = sample();
    const { pos } = layoutByDepth(nodes, edges);
    for (const n of nodes) expect(pos.has(n.id)).toBe(true);
    const plain = nodes.filter((n) => n.kind !== "k8s_cluster");
    for (let i = 0; i < plain.length; i++) {
      for (let j = i + 1; j < plain.length; j++) {
        expect(overlaps(pos.get(plain[i].id) as Placement, pos.get(plain[j].id) as Placement)).toBe(false);
      }
    }
    for (const e of edges.filter((e) => e.kind === "member_of" && e.to.startsWith("k8s"))) {
      expect(inside(pos.get(e.from) as Placement, pos.get(e.to) as Placement)).toBe(true);
    }
  });

  it("survives a runs_on cycle", async () => {
    const { layoutByDepth } = await import("./asset-layout");
    const nodes = [host("a", "vm"), host("b", "vm")];
    const { pos } = layoutByDepth(nodes, [
      { from: "a", to: "b", kind: "runs_on" },
      { from: "b", to: "a", kind: "runs_on" },
    ]);
    expect(pos.size).toBe(2);
  });
});

describe("bastion placement", () => {
  it("puts a bastion directly above the cluster it fronts", () => {
    const { nodes, edges } = sample();
    nodes.push(host("bastion-a", "vm"));
    edges.push({ from: "bastion-a", to: "k8s-a", kind: "gateway_of" });
    const pos = layoutAssets(nodes, edges);
    const bastion = pos.get("bastion-a") as Placement;
    const box = pos.get("k8s-a") as Placement;
    expect(bastion.y + NODE_H).toBeLessThan(box.y);
    expect(bastion.x).toBeGreaterThanOrEqual(box.x);
    expect(bastion.x + NODE_W).toBeLessThanOrEqual(box.x + (box.w ?? 0));
    // It is not a member: it must stay outside the box and clear of everything else.
    expect(inside(bastion, box)).toBe(false);
    for (const n of nodes.filter((n) => n.id !== "bastion-a")) {
      expect(overlaps(bastion, pos.get(n.id) as Placement)).toBe(false);
    }
  });
});

describe("edge crossings", () => {
  // Counts pairs of "runs on" edges whose guests and hosts are in opposite
  // left-to-right order: with guests above and hosts below, that is a crossing.
  const crossings = (pos: Map<string, Placement>, edges: AssetEdge[]) => {
    const runs = edges.filter((e) => e.kind === "runs_on");
    let n = 0;
    for (let i = 0; i < runs.length; i++) {
      for (let j = i + 1; j < runs.length; j++) {
        const top = (pos.get(runs[i].from) as Placement).x - (pos.get(runs[j].from) as Placement).x;
        const bottom = (pos.get(runs[i].to) as Placement).x - (pos.get(runs[j].to) as Placement).x;
        if (top * bottom < 0) n++;
      }
    }
    return n;
  };

  it("orders physical hosts by where their guests are, not by name", () => {
    // Host "a-right" runs the VMs of the right-hand cluster and "z-left" those of
    // the left-hand one: by name they would sit the wrong way round and cross.
    const nodes: AssetNode[] = [cluster("k8s-left"), cluster("k8s-right"), host("a-right"), host("z-left")];
    const edges: AssetEdge[] = [];
    for (let i = 0; i < 6; i++) {
      nodes.push(host(`l${i}`, "vm"), host(`r${i}`, "vm"));
      edges.push(
        { from: `l${i}`, to: "k8s-left", kind: "member_of" },
        { from: `l${i}`, to: "z-left", kind: "runs_on" },
      );
      // The right cluster is the smaller one, so the layout puts it second.
      if (i < 3) {
        edges.push(
          { from: `r${i}`, to: "k8s-right", kind: "member_of" },
          { from: `r${i}`, to: "a-right", kind: "runs_on" },
        );
      }
    }
    const pos = layoutAssets(nodes, edges);
    expect((pos.get("z-left") as Placement).x).toBeLessThan((pos.get("a-right") as Placement).x);
    expect(crossings(pos, edges)).toBe(0);
    expect(overlaps(pos.get("z-left") as Placement, pos.get("a-right") as Placement)).toBe(false);
    expect((pos.get("z-left") as Placement).y).toBe((pos.get("a-right") as Placement).y);
  });

  it("orders unboxed VMs by their host", () => {
    // By name "a-vm" comes first, but it runs on the right-hand host.
    const nodes: AssetNode[] = [
      cluster("k8s"),
      host("hv-left"),
      host("hv-right"),
      host("a-vm", "vm"),
      host("b-vm", "vm"),
    ];
    const edges: AssetEdge[] = [
      { from: "a-vm", to: "hv-right", kind: "runs_on" },
      { from: "b-vm", to: "hv-left", kind: "runs_on" },
    ];
    for (let i = 0; i < 4; i++) {
      nodes.push(host(`n${i}`, "vm"));
      edges.push({ from: `n${i}`, to: "k8s", kind: "member_of" }, { from: `n${i}`, to: "hv-left", kind: "runs_on" });
    }
    const pos = layoutAssets(nodes, edges);
    expect((pos.get("hv-left") as Placement).x).toBeLessThan((pos.get("hv-right") as Placement).x);
    expect((pos.get("b-vm") as Placement).x).toBeLessThan((pos.get("a-vm") as Placement).x);
    expect(crossings(pos, edges)).toBe(0);
  });

  it("keeps hosts without guests in the row, clear of the others", () => {
    const nodes: AssetNode[] = [host("hv1"), host("spare"), host("vm1", "vm")];
    const edges: AssetEdge[] = [{ from: "vm1", to: "hv1", kind: "runs_on" }];
    const pos = layoutAssets(nodes, edges);
    expect((pos.get("spare") as Placement).y).toBe((pos.get("hv1") as Placement).y);
    expect(overlaps(pos.get("spare") as Placement, pos.get("hv1") as Placement)).toBe(false);
    for (const n of nodes) expect((pos.get(n.id) as Placement).x).toBeGreaterThanOrEqual(0);
  });
});

describe("bastions in the depth layout", () => {
  it("shows bastions as a service group beside OpenStack, not as a depth", async () => {
    const { layoutByDepth } = await import("./asset-layout");
    const { nodes, edges } = sample();
    nodes.push(host("bastion-a", "vm"), host("bastion-b", "vm"));
    edges.push(
      { from: "bastion-a", to: "k8s-a", kind: "gateway_of" },
      { from: "bastion-b", to: "k8s-b", kind: "gateway_of" },
    );
    const { pos, tiers, frames } = layoutByDepth(nodes, edges);
    const at = (id: string) => pos.get(id) as Placement;

    // No row of their own between the levels: groups, physical hosts, VMs.
    expect(tiers.map((t) => t.depth)).toEqual([-1, 0, 1]);
    // OpenStack and the bastion frame are the two service groups.
    expect(tiers[0].count).toBe(2);
    // The bastions are not counted among the VMs.
    expect(tiers[2].count).toBe(nodes.filter((n) => n.kind === "vm" && !n.id.startsWith("bastion")).length);

    expect(frames).toHaveLength(1);
    const frame = frames[0];
    expect(frame.count).toBe(2);
    expect(frame.y).toBe(at("os").y);
    expect(frame.x).toBeGreaterThan(at("os").x + NODE_W);
    for (const id of ["bastion-a", "bastion-b"]) expect(inside(at(id), frame)).toBe(true);
    // Everything below starts under the frame, and nothing else touches it.
    expect(at("hv1").y).toBeGreaterThan(frame.y + frame.h);
    for (const n of nodes.filter((n) => !n.id.startsWith("bastion"))) expect(overlaps(at(n.id), frame)).toBe(false);
  });

  it("still shows the group row when there are bastions but no OpenStack", async () => {
    const { layoutByDepth } = await import("./asset-layout");
    const nodes: AssetNode[] = [cluster("k8s"), host("n1", "vm"), host("jump", "vm")];
    const edges: AssetEdge[] = [
      { from: "n1", to: "k8s", kind: "member_of" },
      { from: "jump", to: "k8s", kind: "gateway_of" },
    ];
    const { pos, tiers, frames } = layoutByDepth(nodes, edges);
    expect(tiers[0]).toMatchObject({ depth: -1, count: 1 });
    expect(frames).toHaveLength(1);
    expect((pos.get("jump") as Placement).y).toBeLessThan((pos.get("n1") as Placement).y);
  });

  it("draws no frame when nothing fronts a cluster", async () => {
    const { layoutByDepth } = await import("./asset-layout");
    const { nodes, edges } = sample();
    expect(layoutByDepth(nodes, edges).frames).toHaveLength(0);
  });
});

describe("depth layout line crossings", () => {
  // Straight lines between node centres; counts pairs that properly intersect.
  const segmentCrossings = (pos: Map<string, Placement>, edges: AssetEdge[]) => {
    const mid = (id: string) => {
      const r = rect(pos.get(id) as Placement);
      return { x: r.x + r.w / 2, y: r.y + r.h / 2 };
    };
    const side = (a: { x: number; y: number }, b: { x: number; y: number }, c: { x: number; y: number }) =>
      Math.sign((b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x));
    const lines = edges.filter((e) => pos.has(e.from) && pos.has(e.to)).map((e) => [mid(e.from), mid(e.to)] as const);
    let n = 0;
    for (let i = 0; i < lines.length; i++) {
      for (let j = i + 1; j < lines.length; j++) {
        const [a, b] = lines[i];
        const [c, d] = lines[j];
        if (side(a, b, c) * side(a, b, d) < 0 && side(c, d, a) * side(c, d, b) < 0) n++;
      }
    }
    return n;
  };

  // Shaped like a real deployment: two physical hosts each running a small
  // cluster and a single VM, three larger clusters on unknown hypervisors,
  // each behind its own bastion.
  function deployment() {
    const nodes: AssetNode[] = [{ id: "os", kind: "openstack", name: "os" }, host("hv-a"), host("hv-b")];
    const edges: AssetEdge[] = [
      { from: "hv-a", to: "os", kind: "member_of" },
      { from: "hv-b", to: "os", kind: "member_of" },
    ];
    const vm = (id: string, clusterId?: string, hv?: string) => {
      nodes.push(host(id, "vm"));
      if (clusterId) edges.push({ from: id, to: clusterId, kind: "member_of" });
      if (hv) edges.push({ from: id, to: hv, kind: "runs_on" });
    };
    for (const c of ["small-a", "small-b", "big-1", "big-2", "big-3"]) nodes.push(cluster(c));
    // Names chosen so that name order disagrees with host order.
    vm("z-single", undefined, "hv-a");
    vm("a-single", undefined, "hv-b");
    for (let i = 0; i < 2; i++) vm(`sa${i}`, "small-a", "hv-b");
    for (let i = 0; i < 2; i++) vm(`sb${i}`, "small-b", "hv-a");
    for (let i = 0; i < 6; i++) vm(`b1-${i}`, "big-1");
    for (let i = 0; i < 9; i++) vm(`b2-${i}`, "big-2");
    for (let i = 0; i < 3; i++) vm(`b3-${i}`, "big-3");
    for (const [bastion, target] of [
      ["z-bastion", "big-1"],
      ["m-bastion", "big-2"],
      ["a-bastion", "big-3"],
    ]) {
      nodes.push(host(bastion, "vm"));
      edges.push({ from: bastion, to: target, kind: "gateway_of" });
    }
    return { nodes, edges };
  }

  it("draws a realistic deployment without a single crossing", async () => {
    const { layoutByDepth } = await import("./asset-layout");
    const { nodes, edges } = deployment();
    const { pos } = layoutByDepth(nodes, edges);
    // Cluster membership is drawn as a box, not a line.
    const lines = edges.filter((e) => e.kind !== "member_of" || e.to === "os");
    expect(segmentCrossings(pos, lines)).toBe(0);
  });

  it("keeps every level on one row and every node clear of the others", async () => {
    const { layoutByDepth } = await import("./asset-layout");
    const { nodes, edges } = deployment();
    const { pos, tiers } = layoutByDepth(nodes, edges);
    const at = (id: string) => pos.get(id) as Placement;
    // All cluster boxes of the VM level start at the level's y: nothing wrapped.
    const vmTier = tiers.find((t) => t.depth === 1);
    for (const c of ["small-a", "small-b", "big-1", "big-2", "big-3"]) expect(at(c).y).toBe(vmTier?.y);
    const plain = nodes.filter((n) => n.kind !== "k8s_cluster");
    for (let i = 0; i < plain.length; i++) {
      for (let j = i + 1; j < plain.length; j++) expect(overlaps(at(plain[i].id), at(plain[j].id))).toBe(false);
    }
    for (const n of nodes) expect(at(n.id).x).toBeGreaterThanOrEqual(0);
    // The physical hosts are level with each other, whatever the column count below.
    expect(at("hv-a").y).toBe(at("hv-b").y);
    expect(at("hv-a").y).toBe(tiers.find((t) => t.depth === 0)?.y);
    // Hosts sit over their own guests, bastions in the order of their clusters.
    expect(at("hv-a").x < at("hv-b").x).toBe(at("small-b").x < at("small-a").x);
    expect(at("z-bastion").x < at("m-bastion").x).toBe(at("big-1").x < at("big-2").x);
    expect(at("m-bastion").x < at("a-bastion").x).toBe(at("big-2").x < at("big-3").x);
  });
});
