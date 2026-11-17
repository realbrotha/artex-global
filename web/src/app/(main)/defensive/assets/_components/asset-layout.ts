import { type AssetEdge, type AssetNode, isHostNode } from "@/lib/wazuh-api";

// Wide enough for a 30-character host name on two lines beside the icon;
// tall enough for the name, the private address and the public address.
export const NODE_W = 200;
export const NODE_H = 70;

const CELL_GAP_X = 12;
const CELL_GAP_Y = 14;
const BOX_PAD = 14;
const BOX_HEADER = 40;
const BOX_COLS = 3;
const BLOCK_GAP = 36;
const ROW_GAP = 96;
const LINE_W = 1500;
// Space between a cluster box and the bastion drawn above it.
const GATEWAY_GAP = 26;

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
//   - every Kubernetes cluster is a box that contains its nodes, with its
//     bastion (the jump host on its network) directly above the box
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

  const gatewayOf = new Map<string, string>();
  for (const e of edges) {
    if (e.kind === "gateway_of" && hostIds.has(e.from) && clusterIds.has(e.to) && !gatewayOf.has(e.from)) {
      gatewayOf.set(e.from, e.to);
    }
  }

  const byName = (a: AssetNode, b: AssetNode) => a.name.localeCompare(b.name);
  const members = new Map<string, AssetNode[]>();
  const gateways = new Map<string, AssetNode[]>();
  const looseGuests: AssetNode[] = [];
  const infra: AssetNode[] = [];
  for (const h of [...hosts].sort(byName)) {
    const cluster = clusterOf.get(h.id);
    const fronts = gatewayOf.get(h.id);
    if (cluster) members.set(cluster, [...(members.get(cluster) ?? []), h]);
    else if (fronts) gateways.set(fronts, [...(gateways.get(fronts) ?? []), h]);
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
    const front = gateways.get(cluster.id) ?? [];
    const grid = gridSize(list.length, BOX_COLS);
    const frontW = front.length * NODE_W + Math.max(0, front.length - 1) * CELL_GAP_X;
    const w = Math.max(grid.w + 2 * BOX_PAD, frontW);
    const h = BOX_HEADER + grid.h + BOX_PAD;
    // The bastion row sits on top of the box, inside the same block.
    const lift = front.length > 0 ? NODE_H + GATEWAY_GAP : 0;
    const at = place(w, h + lift);
    front.forEach((n, i) => {
      pos.set(n.id, { x: at.x + i * (NODE_W + CELL_GAP_X), y: at.y });
    });
    pos.set(cluster.id, { x: at.x, y: at.y + lift, w, h });
    fill(list, BOX_COLS, at.x + BOX_PAD, at.y + lift + BOX_HEADER);
  }
  // Where the unboxed VMs go; kept so they can be re-ordered once the hosts are placed.
  let loose: { cols: number; x: number; y: number } | undefined;
  if (looseGuests.length > 0) {
    const cols = Math.min(2, looseGuests.length);
    const grid = gridSize(looseGuests.length, cols);
    loose = { cols, ...place(grid.w, grid.h) };
    fill(looseGuests, cols, loose.x, loose.y);
  }

  const hasTop = ordered.length > 0 || looseGuests.length > 0;
  const centred = (list: AssetNode[], top: number, around?: number) => {
    const step = NODE_W + BLOCK_GAP;
    const total = list.length * step - BLOCK_GAP;
    const start = Math.max(0, (around ?? maxX / 2) - total / 2);
    list.forEach((n, i) => {
      pos.set(n.id, { x: start + i * step, y: top });
    });
  };

  // Physical hosts go under their own guests: each host aims for the mean x of
  // the VMs that run on it (the barycentre), and the row is ordered by that
  // aim. Two hosts whose guests sit left and right then stay left and right,
  // so their "runs on" edges do not cross each other.
  const infraY = hasTop ? y + rowH + ROW_GAP : 0;
  const hostOf = new Map<string, string>();
  for (const e of edges) {
    if (e.kind === "runs_on" && hostIds.has(e.from) && hostIds.has(e.to) && !hostOf.has(e.from))
      hostOf.set(e.from, e.to);
  }
  const placeInfra = () => {
    const guestXs = new Map<string, number[]>();
    for (const [guest, hv] of hostOf) {
      const at = pos.get(guest);
      if (at) guestXs.set(hv, [...(guestXs.get(hv) ?? []), at.x + NODE_W / 2]);
    }
    const aim = (h: AssetNode) => {
      const xs = guestXs.get(h.id);
      return xs ? xs.reduce((sum, v) => sum + v, 0) / xs.length : undefined;
    };
    const anchored = infra
      .filter((h) => aim(h) !== undefined)
      .sort((a, b) => (aim(a) as number) - (aim(b) as number) || byName(a, b));
    const adrift = infra.filter((h) => aim(h) === undefined);
    if (anchored.length === 0) {
      centred(infra, infraY);
      return infra;
    }
    // Sweep left to right so neighbours keep their distance, then pull the
    // row back if the sweep pushed it past where it aimed.
    const step = NODE_W + BLOCK_GAP;
    const xs: number[] = [];
    anchored.forEach((h, i) => {
      const want = (aim(h) as number) - NODE_W / 2;
      xs.push(i === 0 ? Math.max(0, want) : Math.max(want, xs[i - 1] + step));
    });
    const drift = xs[xs.length - 1] - ((aim(anchored[anchored.length - 1]) as number) - NODE_W / 2);
    const shift = Math.min(drift / 2, xs[0]);
    anchored.forEach((h, i) => {
      pos.set(h.id, { x: xs[i] - shift, y: infraY });
    });
    // Hosts that run nothing we know of line up after the anchored ones.
    adrift.forEach((h, i) => {
      pos.set(h.id, { x: xs[xs.length - 1] - shift + (i + 1) * step, y: infraY });
    });
    return [...anchored, ...adrift];
  };

  // Second pass: the unboxed VMs take the left-to-right order of their hosts,
  // so a VM on the left host is not drawn to the right of one on the right
  // host. The hosts are then placed again under the settled VMs.
  const order = placeInfra();
  if (loose && looseGuests.length > 1) {
    const rank = new Map(order.map((h, i) => [h.id, i]));
    const of = (n: AssetNode) => rank.get(hostOf.get(n.id) ?? "") ?? order.length;
    fill(
      [...looseGuests].sort((a, b) => of(a) - of(b) || byName(a, b)),
      loose.cols,
      loose.x,
      loose.y,
    );
    placeInfra();
  }

  // OpenStack sits under the middle of the hosts it is made of.
  const openstack = nodes.filter((n) => n.kind === "openstack");
  const infraXs = infra.map((h) => (pos.get(h.id)?.x ?? 0) + NODE_W / 2);
  const infraMid = infraXs.length > 0 ? (Math.min(...infraXs) + Math.max(...infraXs)) / 2 : undefined;
  centred(openstack, infra.length > 0 ? infraY + NODE_H + ROW_GAP : infraY, infraMid);
  return pos;
}

// One horizontal band of the depth layout. depth -1 is the service-group row
// (OpenStack) above the hosts.
export interface Tier {
  depth: number;
  y: number;
  count: number;
}

export const TIER_LABEL_W = 132;
const TIER_COLS = 4;
const MAX_DEPTH = 8;

// Lays the map out top-down by how deep a host sits in the "runs on" chain:
//
//   - service groups (OpenStack) on top
//   - depth 0: hosts that run on nothing we know of (physical machines)
//   - depth 1: their guests, depth 2: guests of guests, and so on
//
// A VM whose hypervisor is unknown still sits at depth 1: it runs on
// something, just not on a host with an agent. Within a tier, hosts follow
// their parent's order, and members of one Kubernetes cluster share a box.
export function layoutByDepth(nodes: AssetNode[], edges: AssetEdge[]): { pos: Map<string, Placement>; tiers: Tier[] } {
  const pos = new Map<string, Placement>();
  const tiers: Tier[] = [];
  const hosts = nodes.filter(isHostNode);
  const hostIds = new Set(hosts.map((h) => h.id));
  const clusterIds = new Set(nodes.filter((n) => n.kind === "k8s_cluster").map((c) => c.id));

  const clusterOf = new Map<string, string>();
  const parentOf = new Map<string, string>();
  for (const e of edges) {
    if (e.kind === "member_of" && hostIds.has(e.from) && clusterIds.has(e.to) && !clusterOf.has(e.from)) {
      clusterOf.set(e.from, e.to);
    }
    if (e.kind === "runs_on" && hostIds.has(e.from) && hostIds.has(e.to) && !parentOf.has(e.from)) {
      parentOf.set(e.from, e.to);
    }
  }

  const kindOf = new Map(hosts.map((h) => [h.id, h.kind]));
  const depthOf = (id: string): number => {
    let depth = 0;
    let at = id;
    // The hop limit also ends a (malformed) cycle.
    for (let hops = 0; hops < MAX_DEPTH; hops++) {
      const parent = parentOf.get(at);
      if (!parent) return depth + (kindOf.get(at) === "vm" ? 1 : 0);
      depth += 1;
      at = parent;
    }
    return depth;
  };

  const byDepth = new Map<number, AssetNode[]>();
  for (const h of hosts) {
    const d = depthOf(h.id);
    byDepth.set(d, [...(byDepth.get(d) ?? []), h]);
  }

  const x0 = TIER_LABEL_W;
  let y = 0;
  const groups = nodes.filter((n) => n.kind === "openstack").sort((a, b) => a.name.localeCompare(b.name));
  if (groups.length > 0) {
    groups.forEach((g, i) => {
      pos.set(g.id, { x: x0 + i * (NODE_W + BLOCK_GAP), y });
    });
    tiers.push({ depth: -1, y, count: groups.length });
    y += NODE_H + ROW_GAP;
  }

  // Order within a tier: parent's rank first, so guests sit under their host.
  const rank = new Map<string, number>();
  for (const depth of [...byDepth.keys()].sort((a, b) => a - b)) {
    const list = (byDepth.get(depth) ?? []).sort(
      (a, b) =>
        (rank.get(parentOf.get(a.id) ?? "") ?? Number.MAX_SAFE_INTEGER) -
          (rank.get(parentOf.get(b.id) ?? "") ?? Number.MAX_SAFE_INTEGER) ||
        (clusterOf.get(a.id) ?? "").localeCompare(clusterOf.get(b.id) ?? "") ||
        a.name.localeCompare(b.name),
    );
    list.forEach((h, i) => {
      rank.set(h.id, i);
    });

    // Blocks: one per cluster (in order of first member), loose hosts between.
    const blocks: { cluster?: string; members: AssetNode[] }[] = [];
    for (const h of list) {
      const cluster = clusterOf.get(h.id);
      const open = blocks.find((b) => cluster !== undefined && b.cluster === cluster);
      const last = blocks.at(-1);
      if (open) open.members.push(h);
      else if (cluster === undefined && last && last.cluster === undefined) last.members.push(h);
      else blocks.push({ cluster, members: [h] });
    }

    const top = y;
    let x = x0;
    let rowH = 0;
    for (const block of blocks) {
      const cols = Math.min(TIER_COLS, block.members.length);
      const grid = gridSize(block.members.length, cols);
      // A cluster drawn in an earlier tier keeps its box there; later members stay loose.
      const boxed = block.cluster !== undefined && !pos.has(block.cluster);
      const w = boxed ? grid.w + 2 * BOX_PAD : grid.w;
      const h = boxed ? BOX_HEADER + grid.h + BOX_PAD : grid.h;
      if (x > x0 && x + w > x0 + LINE_W) {
        x = x0;
        y += rowH + BLOCK_GAP;
        rowH = 0;
      }
      if (boxed && block.cluster !== undefined) pos.set(block.cluster, { x, y, w, h });
      block.members.forEach((n, i) => {
        pos.set(n.id, {
          x: x + (boxed ? BOX_PAD : 0) + (i % cols) * (NODE_W + CELL_GAP_X),
          y: y + (boxed ? BOX_HEADER : 0) + Math.floor(i / cols) * (NODE_H + CELL_GAP_Y),
        });
      });
      x += w + BLOCK_GAP;
      rowH = Math.max(rowH, h);
    }
    tiers.push({ depth, y: top, count: list.length });
    y += rowH + ROW_GAP;
  }

  // Clusters with no member host still need a place.
  let spare = x0;
  for (const id of clusterIds) {
    if (pos.has(id)) continue;
    pos.set(id, { x: spare, y, w: NODE_W + 2 * BOX_PAD, h: BOX_HEADER + BOX_PAD });
    spare += NODE_W + 2 * BOX_PAD + BLOCK_GAP;
  }
  return { pos, tiers };
}
