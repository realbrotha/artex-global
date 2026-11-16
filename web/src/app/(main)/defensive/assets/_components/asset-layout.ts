import { type AssetEdge, type AssetNode, isHostNode } from "@/lib/wazuh-api";

export const NODE_W = 184;
export const NODE_H = 56;

const CELL_GAP_X = 12;
const CELL_GAP_Y = 14;
const BOX_PAD = 14;
const BOX_HEADER = 40;
const BOX_COLS = 3;
const BLOCK_GAP = 36;
const ROW_GAP = 96;
const LINE_W = 1500;

// A cluster box carries a size; every other node is NODE_W x NODE_H.
export interface Placement {
  x: number;
  y: number;
  w?: number;
  h?: number;
}

function gridSize(count: number, cols: number) {
  const usedCols = Math.max(1, Math.min(cols, count));
  const rows = Math.max(1, Math.ceil(count / cols));
  return {
    w: usedCols * NODE_W + (usedCols - 1) * CELL_GAP_X,
    h: rows * NODE_H + (rows - 1) * CELL_GAP_Y,
  };
}

// Lays the map out so that membership needs no lines:
//
//   - every Kubernetes cluster is a box that contains its nodes
//   - VMs outside any cluster form one unboxed group beside the boxes
//   - physical hosts sit in a row underneath, so "runs on" edges point down
//   - OpenStack sits below the physical hosts it is made of
//
// Only "runs on" and OpenStack membership remain as edges.
export function layoutAssets(nodes: AssetNode[], edges: AssetEdge[]): Map<string, Placement> {
  const pos = new Map<string, Placement>();
  const hosts = nodes.filter(isHostNode);
  const hostIds = new Set(hosts.map((h) => h.id));
  const clusters = nodes.filter((n) => n.kind === "k8s_cluster");
  const clusterIds = new Set(clusters.map((c) => c.id));

  const clusterOf = new Map<string, string>();
  const hasGuests = new Set<string>();
  for (const e of edges) {
    if (e.kind === "member_of" && hostIds.has(e.from) && clusterIds.has(e.to) && !clusterOf.has(e.from)) {
      clusterOf.set(e.from, e.to);
    }
    if (e.kind === "runs_on" && hostIds.has(e.from) && hostIds.has(e.to)) hasGuests.add(e.to);
  }

  const byName = (a: AssetNode, b: AssetNode) => a.name.localeCompare(b.name);
  const members = new Map<string, AssetNode[]>();
  const looseGuests: AssetNode[] = [];
  const infra: AssetNode[] = [];
  for (const h of [...hosts].sort(byName)) {
    const cluster = clusterOf.get(h.id);
    if (cluster) members.set(cluster, [...(members.get(cluster) ?? []), h]);
    else if (h.kind === "baremetal" || hasGuests.has(h.id)) infra.push(h);
    else looseGuests.push(h);
  }

  // Flow blocks left to right, wrapping at LINE_W.
  let x = 0;
  let y = 0;
  let rowH = 0;
  let maxX = 0;
  const place = (w: number, h: number) => {
    if (x > 0 && x + w > LINE_W) {
      x = 0;
      y += rowH + BLOCK_GAP;
      rowH = 0;
    }
    const at = { x, y };
    x += w + BLOCK_GAP;
    rowH = Math.max(rowH, h);
    maxX = Math.max(maxX, x - BLOCK_GAP);
    return at;
  };
  const fill = (list: AssetNode[], cols: number, ox: number, oy: number) => {
    list.forEach((n, i) => {
      pos.set(n.id, {
        x: ox + (i % cols) * (NODE_W + CELL_GAP_X),
        y: oy + Math.floor(i / cols) * (NODE_H + CELL_GAP_Y),
      });
    });
  };

  // Largest clusters first so the big boxes anchor the top-left.
  const ordered = [...clusters].sort(
    (a, b) => (members.get(b.id)?.length ?? 0) - (members.get(a.id)?.length ?? 0) || byName(a, b),
  );
  for (const cluster of ordered) {
    const list = members.get(cluster.id) ?? [];
    const grid = gridSize(list.length, BOX_COLS);
    const w = grid.w + 2 * BOX_PAD;
    const h = BOX_HEADER + grid.h + BOX_PAD;
    const at = place(w, h);
    pos.set(cluster.id, { ...at, w, h });
    fill(list, BOX_COLS, at.x + BOX_PAD, at.y + BOX_HEADER);
  }
  if (looseGuests.length > 0) {
    const cols = Math.min(2, looseGuests.length);
    const grid = gridSize(looseGuests.length, cols);
    const at = place(grid.w, grid.h);
    fill(looseGuests, cols, at.x, at.y);
  }

  const hasTop = ordered.length > 0 || looseGuests.length > 0;
  const centred = (list: AssetNode[], top: number) => {
    const step = NODE_W + BLOCK_GAP;
    const total = list.length * step - BLOCK_GAP;
    const start = Math.max(0, (maxX - total) / 2);
    list.forEach((n, i) => {
      pos.set(n.id, { x: start + i * step, y: top });
    });
  };
  const infraY = hasTop ? y + rowH + ROW_GAP : 0;
  centred(infra, infraY);
  const openstack = nodes.filter((n) => n.kind === "openstack");
  centred(openstack, infra.length > 0 ? infraY + NODE_H + ROW_GAP : infraY);
  return pos;
}
