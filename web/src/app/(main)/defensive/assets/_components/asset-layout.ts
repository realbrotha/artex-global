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

// A labelled outline around hosts that share a role but are not a cluster:
// the bastions, shown as a service group.
export interface Frame {
  id: string;
  x: number;
  y: number;
  w: number;
  h: number;
  count: number;
}

export const TIER_LABEL_W = 132;
const MAX_DEPTH = 8;
// Width-to-height ratio the map is usually shown at; used to pick how many
// columns a block gets so the whole picture fits with the largest zoom.
const VIEW_ASPECT = 1.7;

const mean = (xs: number[]) => xs.reduce((sum, v) => sum + v, 0) / xs.length;

// Spreads items along a row: each keeps the x it asked for when it can, and
// is pushed right just far enough to clear its left neighbour.
function sweep<T>(items: T[], want: (item: T) => number, width: (item: T) => number, gap: number, min: number) {
  const out = new Map<T, number>();
  let next = min;
  for (const item of [...items].sort((a, b) => want(a) - want(b))) {
    const x = Math.max(want(item), next);
    out.set(item, x);
    next = x + width(item) + gap;
  }
  return out;
}

// Lays the map out top-down by how deep a host sits in the "runs on" chain,
// arranged so the lines cross as little as possible (a layered layout with
// barycentre ordering, as in Sugiyama-style graph drawing):
//
//   - service groups on top: OpenStack, and the bastions as one framed group
//     (a role the hosts play, like OpenStack, rather than a depth)
//   - depth 0: hosts that run on nothing we know of (physical machines)
//   - depth 1: their guests, depth 2: guests of guests, and so on
//
// What keeps the lines apart:
//
//   - every level is ONE row, never wrapped: a line to a block in a second
//     row would have to pass through the blocks of the first
//   - guests follow the left-to-right order of their hosts
//   - a host sits over the middle of its guests, OpenStack over the middle of
//     its hosts, and each bastion over the cluster it fronts
//
// A VM whose hypervisor is unknown still sits at depth 1: it runs on
// something, just not on a host with an agent. Members of one Kubernetes
// cluster share a box; the box is as narrow as the view allows, so one row
// still fits the screen.
export function layoutByDepth(
  nodes: AssetNode[],
  edges: AssetEdge[],
): { pos: Map<string, Placement>; tiers: Tier[]; frames: Frame[] } {
  const pos = new Map<string, Placement>();
  const tiers: Tier[] = [];
  const frames: Frame[] = [];
  const hosts = nodes.filter(isHostNode);
  const hostIds = new Set(hosts.map((h) => h.id));
  const clusterIds = new Set(nodes.filter((n) => n.kind === "k8s_cluster").map((c) => c.id));
  const byName = (a: AssetNode, b: AssetNode) => a.name.localeCompare(b.name);

  const clusterOf = new Map<string, string>();
  const parentOf = new Map<string, string>();
  const gatewayOf = new Map<string, string>();
  for (const e of edges) {
    if (!hostIds.has(e.from)) continue;
    if (e.kind === "member_of" && clusterIds.has(e.to) && !clusterOf.has(e.from)) clusterOf.set(e.from, e.to);
    if (e.kind === "runs_on" && hostIds.has(e.to) && !parentOf.has(e.from)) parentOf.set(e.from, e.to);
    if (e.kind === "gateway_of" && clusterIds.has(e.to) && !gatewayOf.has(e.from)) gatewayOf.set(e.from, e.to);
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

  // Bastions are a service group, like OpenStack: what matters about them is
  // the role (the way in to a cluster), not how deep they run.
  const gateways = hosts.filter((h) => gatewayOf.has(h.id));
  const byDepth = new Map<number, AssetNode[]>();
  for (const h of hosts) {
    if (gatewayOf.has(h.id)) continue;
    const d = depthOf(h.id);
    byDepth.set(d, [...(byDepth.get(d) ?? []), h]);
  }
  const depths = [...byDepth.keys()].sort((a, b) => a - b);

  // Blocks of each level, in order: guests follow their host's rank, and the
  // members of one cluster form one block.
  interface Block {
    cluster?: string;
    members: AssetNode[];
  }
  const rank = new Map<string, number>();
  const blocksOf = new Map<number, Block[]>();
  const boxedAt = new Map<string, number>();
  for (const depth of depths) {
    const list = (byDepth.get(depth) ?? []).sort(
      (a, b) =>
        (rank.get(parentOf.get(a.id) ?? "") ?? Number.MAX_SAFE_INTEGER) -
          (rank.get(parentOf.get(b.id) ?? "") ?? Number.MAX_SAFE_INTEGER) ||
        (clusterOf.get(a.id) ?? "").localeCompare(clusterOf.get(b.id) ?? "") ||
        byName(a, b),
    );
    list.forEach((h, i) => {
      rank.set(h.id, i);
    });
    const blocks: Block[] = [];
    for (const h of list) {
      // A cluster is boxed in the first level it appears in; members deeper down stay loose.
      const own = clusterOf.get(h.id);
      const cluster = own !== undefined && (boxedAt.get(own) ?? depth) === depth ? own : undefined;
      if (cluster !== undefined) boxedAt.set(cluster, depth);
      const open = blocks.find((b) => cluster !== undefined && b.cluster === cluster);
      const last = blocks.at(-1);
      // Loose hosts share a block only while they share a host, so each run sits
      // under its own. The top level has no hosts above it: there every machine
      // is a block of its own, which keeps the whole level on one line however
      // narrow the blocks below are made.
      const sameHost =
        depth !== depths[0] && last?.members.length ? parentOf.get(last.members[0].id) === parentOf.get(h.id) : false;
      if (open) open.members.push(h);
      else if (cluster === undefined && last && last.cluster === undefined && sameHost) last.members.push(h);
      else blocks.push({ cluster, members: [h] });
    }
    blocksOf.set(depth, blocks);
  }

  const sizeOf = (block: Block, cols: number) => {
    const grid = gridSize(block.members.length, Math.min(cols, block.members.length));
    return block.cluster === undefined ? grid : { w: grid.w + 2 * BOX_PAD, h: BOX_HEADER + grid.h + BOX_PAD };
  };
  const frameSize =
    gateways.length > 0
      ? (() => {
          const grid = gridSize(gateways.length, gateways.length);
          return { w: grid.w + 2 * BOX_PAD, h: BOX_HEADER + grid.h + BOX_PAD };
        })()
      : undefined;
  const groups = nodes.filter((n) => n.kind === "openstack").sort(byName);
  const hasGroupRow = groups.length > 0 || gateways.length > 0;
  const groupRowH = hasGroupRow ? Math.max(groups.length > 0 ? NODE_H : 0, frameSize?.h ?? 0) : 0;

  // Fewer columns make a level narrower but taller. Pick the count that lets
  // the whole map be shown largest.
  let cols = 1;
  let best = -1;
  for (const candidate of [1, 2, 3, 4]) {
    let width = 0;
    let height = hasGroupRow ? groupRowH + ROW_GAP : 0;
    for (const depth of depths) {
      const sizes = (blocksOf.get(depth) ?? []).map((b) => sizeOf(b, candidate));
      width = Math.max(width, sizes.reduce((sum, s) => sum + s.w, 0) + Math.max(0, sizes.length - 1) * BLOCK_GAP);
      height += Math.max(0, ...sizes.map((s) => s.h)) + ROW_GAP;
    }
    const zoom = Math.min(VIEW_ASPECT / Math.max(1, width + TIER_LABEL_W), 1 / Math.max(1, height));
    if (zoom > best) {
      best = zoom;
      cols = candidate;
    }
  }

  // Rows top to bottom; x is settled afterwards, once every level is known.
  const x0 = TIER_LABEL_W;
  let y = 0;
  if (hasGroupRow) {
    tiers.push({ depth: -1, y, count: groups.length + (gateways.length > 0 ? 1 : 0) });
    y += groupRowH + ROW_GAP;
  }
  const groupY = 0;
  for (const depth of depths) {
    const blocks = blocksOf.get(depth) ?? [];
    let x = x0;
    let rowH = 0;
    for (const block of blocks) {
      const size = sizeOf(block, cols);
      const boxed = block.cluster !== undefined;
      const used = Math.min(cols, block.members.length);
      if (block.cluster !== undefined) pos.set(block.cluster, { x, y, w: size.w, h: size.h });
      block.members.forEach((n, i) => {
        pos.set(n.id, {
          x: x + (boxed ? BOX_PAD : 0) + (i % used) * (NODE_W + CELL_GAP_X),
          y: y + (boxed ? BOX_HEADER : 0) + Math.floor(i / used) * (NODE_H + CELL_GAP_Y),
        });
      });
      x += size.w + BLOCK_GAP;
      rowH = Math.max(rowH, size.h);
    }
    tiers.push({ depth, y, count: (byDepth.get(depth) ?? []).length });
    y += rowH + ROW_GAP;
  }

  const centre = (id: string) => {
    const at = pos.get(id);
    return at ? at.x + (at.w ?? NODE_W) / 2 : undefined;
  };
  const centres = (ids: string[]) => ids.map(centre).filter((v): v is number => v !== undefined);

  // The top level moves over its guests. Only when it is all loose hosts: a
  // boxed level keeps its order, a box cannot be pulled apart.
  const top = depths[0];
  const topBlocks = top === undefined ? [] : (blocksOf.get(top) ?? []);
  if (top !== undefined && topBlocks.every((b) => b.cluster === undefined)) {
    const guestsOf = new Map<string, string[]>();
    for (const [guest, hv] of parentOf) guestsOf.set(hv, [...(guestsOf.get(hv) ?? []), guest]);
    const row = byDepth.get(top) ?? [];
    const aims = new Map(row.map((h) => [h.id, centres(guestsOf.get(h.id) ?? [])]));
    const anchored = row.filter((h) => (aims.get(h.id) ?? []).length > 0);
    const placed = sweep(
      anchored,
      (h) => mean(aims.get(h.id) as number[]) - NODE_W / 2,
      () => NODE_W,
      BLOCK_GAP,
      x0,
    );
    let next = Math.max(x0, ...[...placed.values()].map((x) => x + NODE_W + BLOCK_GAP));
    for (const h of row) {
      const at = pos.get(h.id) as Placement;
      const x = placed.get(h) ?? next;
      if (!placed.has(h)) next += NODE_W + BLOCK_GAP;
      pos.set(h.id, { ...at, x });
    }
  }

  // Service groups: OpenStack over the hosts it is made of, the bastion frame
  // over the clusters it fronts, bastions inside in the order of their clusters.
  if (hasGroupRow) {
    const membersOf = new Map<string, string[]>();
    for (const e of edges) {
      if (e.kind === "member_of" && hostIds.has(e.from)) membersOf.set(e.to, [...(membersOf.get(e.to) ?? []), e.from]);
    }
    type Item = { id: string; w: number; want: number };
    const items: Item[] = groups.map((g, i) => {
      const over = centres(membersOf.get(g.id) ?? []);
      return { id: g.id, w: NODE_W, want: over.length > 0 ? mean(over) - NODE_W / 2 : x0 + i * (NODE_W + BLOCK_GAP) };
    });
    const fronted = (h: AssetNode) => centre(gatewayOf.get(h.id) ?? "") ?? 0;
    const inOrder = [...gateways].sort((a, b) => fronted(a) - fronted(b) || byName(a, b));
    if (frameSize) {
      items.push({ id: "frame", w: frameSize.w, want: mean(inOrder.map(fronted)) - frameSize.w / 2 });
    }
    const placed = sweep(
      items,
      (item) => item.want,
      (item) => item.w,
      BLOCK_GAP,
      x0,
    );
    for (const item of items) {
      const x = placed.get(item) as number;
      if (item.id !== "frame") {
        pos.set(item.id, { x, y: groupY });
        continue;
      }
      if (!frameSize) continue;
      frames.push({ id: "gateways", x, y: groupY, w: frameSize.w, h: frameSize.h, count: gateways.length });
      inOrder.forEach((n, i) => {
        pos.set(n.id, { x: x + BOX_PAD + i * (NODE_W + CELL_GAP_X), y: groupY + BOX_HEADER });
      });
    }
  }

  // Clusters with no member host still need a place.
  let spare = x0;
  for (const id of clusterIds) {
    if (pos.has(id)) continue;
    pos.set(id, { x: spare, y, w: NODE_W + 2 * BOX_PAD, h: BOX_HEADER + BOX_PAD });
    spare += NODE_W + 2 * BOX_PAD + BLOCK_GAP;
  }
  return { pos, tiers, frames };
}
