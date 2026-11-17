"use client";
"use no memo";

import * as React from "react";

import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  type NodeProps,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge as RFEdge,
  type Node as RFNode,
  useNodesState,
  useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { BoxIcon, CircleHelpIcon, DoorOpenIcon, GlobeIcon, ServerIcon, SirenIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { siKubernetes, siOpenstack } from "simple-icons";

import { SimpleIcon } from "@/components/simple-icon";
import { cn } from "@/lib/utils";
import { type AssetEdge, type AssetNode, assetStatusGroup, isHostNode } from "@/lib/wazuh-api";

import { layoutAssets, layoutByDepth, NODE_H, NODE_W, TIER_LABEL_W } from "./asset-layout";
import { severityTone } from "./case-list";

type AssetNodeData = {
  node: AssetNode;
  dim: boolean;
  active: boolean;
  subtitle: string;
  // The host is the bastion of a cluster.
  gateway?: boolean;
  w?: number;
  h?: number;
};
type TierData = { label: string };
type FrameData = { label: string; w: number; h: number };
type AssetRFNode = RFNode<AssetNodeData, "asset" | "cluster"> | RFNode<TierData, "tier"> | RFNode<FrameData, "frame">;
type HostRFNode = RFNode<AssetNodeData, "asset" | "cluster">;

// grouped: clusters as boxes, physical hosts underneath (the original map).
// depth: top-down tiers by how deep a host sits in the "runs on" chain.
type LayoutMode = "grouped" | "depth";
const MODES: LayoutMode[] = ["grouped", "depth"];
const MODE_KEY = "artex.assetMap.layout";

// How a machine is drawn, so the kinds can be told apart at a glance:
//   physical  - square card, heavy border, solid dark server tile
//   OpenStack instance - pill, OpenStack mark (hardware reports OpenStack Nova)
//   other VM  - pill, plain box
//   bastion   - pill, sky door tile (the way in to a cluster)
//   unknown   - dashed tile: agent present, no check result to identify it yet
type Look = "physical" | "openstack-vm" | "vm" | "bastion" | "unknown" | "group";

function lookOf(node: AssetNode, gateway: boolean): Look {
  if (!isHostNode(node)) return "group";
  if (gateway) return "bastion";
  if (node.kind === "baremetal") return "physical";
  if (node.kind === "vm") return /openstack/i.test(node.virt ?? "") ? "openstack-vm" : "vm";
  return "unknown";
}

const tileTone: Record<Look, string> = {
  physical: "rounded-md bg-foreground text-background",
  "openstack-vm": "rounded-full bg-rose-500/10",
  vm: "rounded-full bg-muted text-muted-foreground",
  bastion: "rounded-full bg-sky-500/15 text-sky-700 dark:text-sky-300",
  unknown: "rounded-md border border-dashed text-muted-foreground",
  group: "rounded-full bg-rose-500/10",
};

const statusDot: Record<string, string> = {
  ok: "bg-emerald-500",
  down: "bg-red-500",
  missing: "bg-amber-500",
};

function AssetNodeCard({ data }: NodeProps<HostRFNode>) {
  const { node, dim, active, subtitle, gateway } = data;
  const group = assetStatusGroup(node);
  const look = lookOf(node, Boolean(gateway));
  const square = look === "physical" || look === "unknown";
  // Shown only when it differs from the address already on the row above.
  const publicIp = isHostNode(node) && node.public_ip && node.public_ip !== node.ip ? node.public_ip : "";
  return (
    <div
      className={cn(
        "relative flex items-center gap-2 border bg-card px-2 text-left shadow-xs transition-opacity",
        square ? "rounded-md" : "rounded-full",
        look === "physical" && "border-2 border-foreground/60",
        look === "bastion" && "border-sky-500/60",
        group === "missing" && "border-amber-500 border-dashed",
        active && "ring-2 ring-primary",
        dim && "opacity-25",
      )}
      style={{ width: NODE_W, height: NODE_H }}
    >
      <Handle id="t-in" type="target" position={Position.Top} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="t-out" type="source" position={Position.Top} className="!size-1 !border-0 !bg-transparent" />
      <span className={cn("flex size-8 shrink-0 items-center justify-center", tileTone[look])}>
        {look === "group" && <SimpleIcon icon={siOpenstack} className="size-5 fill-rose-600 dark:fill-rose-400" />}
        {look === "openstack-vm" && (
          <SimpleIcon icon={siOpenstack} className="size-4 fill-rose-600 dark:fill-rose-400" />
        )}
        {look === "physical" && <ServerIcon className="size-4.5" />}
        {look === "vm" && <BoxIcon className="size-4.5" />}
        {look === "bastion" && <DoorOpenIcon className="size-4.5" />}
        {look === "unknown" && <CircleHelpIcon className="size-4.5" />}
      </span>
      {/* Host names are long and hyphenated: the name wraps to two lines and
          the counters sit on the address row, so nothing squeezes the name.
          A host with an external address shows it on a row of its own, under
          the private one, marked with a globe. */}
      <span className="min-w-0 flex-1" title={[node.name, node.ip, node.public_ip].filter(Boolean).join(" · ")}>
        <span className="line-clamp-2 break-words font-medium text-xs leading-[1.15]">{node.name}</span>
        <span className="mt-0.5 flex items-center gap-1">
          <span className="min-w-0 flex-1 truncate text-[10px] text-muted-foreground">{subtitle}</span>
          {(node.cases ?? 0) > 0 && (
            <span
              className={cn(
                "flex shrink-0 items-center gap-0.5 rounded-full border px-1 font-semibold text-[10px] leading-none tabular-nums",
                severityTone[node.case_sev ?? "Low"],
              )}
            >
              <SirenIcon className="size-2.5" />
              {node.cases}
            </span>
          )}
          {(node.checks?.fail ?? 0) > 0 && (
            <span className="shrink-0 rounded-full bg-red-500/15 px-1.5 py-px font-semibold text-[10px] text-red-700 leading-none tabular-nums dark:text-red-300">
              {node.checks?.fail}
            </span>
          )}
        </span>
        {publicIp && (
          <span className="flex items-center gap-0.5 text-[10px] text-sky-700 dark:text-sky-300">
            <GlobeIcon className="size-2.5 shrink-0" />
            <span className="truncate">{publicIp}</span>
          </span>
        )}
      </span>
      {group !== "none" && (
        <span className={cn("absolute -top-1 -right-1 size-2.5 rounded-full ring-2 ring-card", statusDot[group])} />
      )}
      <Handle id="b-in" type="target" position={Position.Bottom} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="b-out" type="source" position={Position.Bottom} className="!size-1 !border-0 !bg-transparent" />
    </div>
  );
}

// A Kubernetes cluster is drawn as a box around its nodes, so membership
// needs no edges.
function ClusterBox({ data }: NodeProps<HostRFNode>) {
  const { node, dim, active, subtitle, w, h } = data;
  return (
    <div
      className={cn(
        "cursor-grab rounded-xl border border-sky-500/40 bg-sky-500/5 transition-opacity active:cursor-grabbing",
        active && "ring-2 ring-primary",
        dim && "opacity-25",
      )}
      style={{ width: w, height: h }}
    >
      {/* Where a bastion's edge lands. */}
      <Handle id="t-in" type="target" position={Position.Top} className="!size-1 !border-0 !bg-transparent" />
      <div className="flex h-10 items-center gap-2 px-3.5">
        <SimpleIcon icon={siKubernetes} className="size-4 shrink-0 fill-sky-600 dark:fill-sky-400" />
        <span className="truncate font-medium text-xs">{node.name}</span>
        <span className="shrink-0 text-[10px] text-muted-foreground">{subtitle}</span>
      </div>
    </div>
  );
}

// Row heading of the depth layout; not a selectable asset.
function TierLabel({ data }: NodeProps<RFNode<TierData, "tier">>) {
  return (
    <div
      className="flex items-center font-medium text-[11px] text-muted-foreground"
      style={{ width: TIER_LABEL_W - 16, height: NODE_H }}
    >
      {data.label}
    </div>
  );
}

// Outline around the bastions of one tier; decoration, not an asset.
function GroupFrame({ data }: NodeProps<RFNode<FrameData, "frame">>) {
  return (
    <div
      className="rounded-xl border border-sky-500/50 border-dashed bg-sky-500/5"
      style={{ width: data.w, height: data.h }}
    >
      <div className="flex h-10 items-center gap-2 px-3.5">
        <DoorOpenIcon className="size-4 shrink-0 text-sky-700 dark:text-sky-300" />
        <span className="truncate font-medium text-xs">{data.label}</span>
      </div>
    </div>
  );
}

const nodeTypes = { asset: AssetNodeCard, cluster: ClusterBox, tier: TierLabel, frame: GroupFrame };

interface AssetGraphProps {
  readonly nodes: AssetNode[];
  readonly edges: AssetEdge[];
  readonly selectedId: string | null;
  readonly onSelect: (id: string | null) => void;
  // Right-click actions. nodeId null = the whole connection named by paneTargets.
  readonly onAnalyze?: (nodeId: string | null, paneTarget?: string) => void;
  readonly onOpenDetail?: (nodeId: string) => void;
  // One entry per connection for the empty-space menu.
  readonly paneTargets?: { id: string; label: string }[];
}

interface MenuState {
  x: number;
  y: number;
  node: AssetNode | null;
}

export function AssetGraph(props: AssetGraphProps) {
  return (
    <ReactFlowProvider>
      <AssetGraphInner {...props} />
    </ReactFlowProvider>
  );
}

function AssetGraphInner({
  nodes,
  edges,
  selectedId,
  onSelect,
  onAnalyze,
  onOpenDetail,
  paneTargets,
}: AssetGraphProps) {
  const t = useTranslations("protectedAssets");

  const flow = useReactFlow();
  const [mode, setMode] = React.useState<LayoutMode>("grouped");
  React.useEffect(() => {
    try {
      const saved = window.localStorage.getItem(MODE_KEY);
      if (MODES.includes(saved as LayoutMode)) setMode(saved as LayoutMode);
    } catch {
      /* storage unavailable: keep the default */
    }
  }, []);

  const { positions, tiers, frames } = React.useMemo(() => {
    if (mode === "depth") {
      const laid = layoutByDepth(nodes, edges);
      return { positions: laid.pos, tiers: laid.tiers, frames: laid.frames };
    }
    return { positions: layoutAssets(nodes, edges), tiers: [], frames: [] };
  }, [nodes, edges, mode]);

  const related = React.useMemo(() => {
    if (!selectedId) return null;
    const set = new Set([selectedId]);
    for (const e of edges) {
      if (e.from === selectedId) set.add(e.to);
      if (e.to === selectedId) set.add(e.from);
    }
    return set;
  }, [edges, selectedId]);

  // Members are children of their cluster box, so dragging the box carries
  // them along. Same membership rule as the layout: first cluster wins.
  const boxOf = React.useMemo(() => {
    const boxes = new Set(nodes.filter((n) => n.kind === "k8s_cluster").map((n) => n.id));
    const hostIds = new Set(nodes.filter(isHostNode).map((n) => n.id));
    const map = new Map<string, string>();
    for (const e of edges) {
      if (e.kind !== "member_of" || !hostIds.has(e.from) || !boxes.has(e.to) || map.has(e.from)) continue;
      // Only a member the layout actually put inside the box is its child.
      const at = positions.get(e.from);
      const box = positions.get(e.to);
      if (!at || !box) continue;
      const inside =
        at.x >= box.x &&
        at.y >= box.y &&
        at.x + NODE_W <= box.x + (box.w ?? 0) &&
        at.y + NODE_H <= box.y + (box.h ?? 0);
      if (inside) map.set(e.from, e.to);
    }
    return map;
  }, [nodes, edges, positions]);

  const gateways = React.useMemo(
    () => new Set(edges.filter((e) => e.kind === "gateway_of").map((e) => e.from)),
    [edges],
  );

  const rfNodes = React.useMemo<AssetRFNode[]>(
    () => [
      ...tiers.map(
        (tier): AssetRFNode => ({
          id: `tier:${tier.depth}`,
          type: "tier",
          position: { x: 0, y: tier.y },
          draggable: false,
          selectable: false,
          data: {
            label:
              tier.depth < 0
                ? t("layout.tierGroups", { count: tier.count })
                : t("layout.tier", { depth: tier.depth + 1, count: tier.count }),
          },
        }),
      ),
      ...frames.map(
        (frame): AssetRFNode => ({
          id: `frame:${frame.id}`,
          type: "frame",
          position: { x: frame.x, y: frame.y },
          draggable: false,
          selectable: false,
          zIndex: -1,
          data: { label: t("layout.gateways", { count: frame.count }), w: frame.w, h: frame.h },
        }),
      ),
      ...// React Flow needs a parent listed before its children.
      [...nodes]
        .sort((a, b) => Number(b.kind === "k8s_cluster") - Number(a.kind === "k8s_cluster"))
        .map((node) => {
          const subtitle = isHostNode(node)
            ? // The private address identifies a host; kind is already the node shape, and
              // roles are in the detail panel. The public address has its own row.
              (node.ip ?? node.public_ip ?? t(`kind.${node.kind}`))
            : t("memberCount", { count: node.members ?? 0 });
          const at = positions.get(node.id) ?? { x: 0, y: 0 };
          const isBox = node.kind === "k8s_cluster";
          const box = boxOf.get(node.id);
          const boxAt = box ? positions.get(box) : undefined;
          return {
            id: node.id,
            type: isBox ? "cluster" : "asset",
            // A member is positioned relative to its box and cannot leave it.
            position: boxAt ? { x: at.x - boxAt.x, y: at.y - boxAt.y } : { x: at.x, y: at.y },
            ...(box && boxAt ? { parentId: box, extent: "parent" as const } : {}),
            zIndex: isBox ? -1 : 0,
            data: {
              node,
              subtitle,
              w: at.w,
              h: at.h,
              active: node.id === selectedId,
              gateway: gateways.has(node.id),
              dim: related !== null && !related.has(node.id),
            },
          } satisfies AssetRFNode;
        }),
    ],
    [nodes, positions, tiers, frames, boxOf, gateways, related, selectedId, t],
  );

  const kindOf = React.useMemo(() => new Map(nodes.map((n) => [n.id, n.kind])), [nodes]);

  const rfEdges = React.useMemo<RFEdge[]>(
    () =>
      edges
        // Cluster membership is shown by containment, not by an edge.
        .filter(
          (e) =>
            kindOf.has(e.from) && kindOf.has(e.to) && (kindOf.get(e.to) !== "k8s_cluster" || e.kind === "gateway_of"),
        )
        .map((e) => {
          const lit = related === null || e.from === selectedId || e.to === selectedId;
          return {
            id: `${e.kind}:${e.from}>${e.to}`,
            source: e.from,
            target: e.to,
            // Grouped: guests sit above their host. Depth: below it.
            // A bastion always points down into the top of its cluster box.
            sourceHandle: mode === "depth" && e.kind !== "gateway_of" ? "t-out" : "b-out",
            targetHandle: mode === "depth" && e.kind !== "gateway_of" ? "b-in" : "t-in",
            style: {
              strokeWidth: e.kind === "runs_on" ? 1.5 : 1,
              strokeDasharray: e.kind === "runs_on" ? undefined : "5 4",
              opacity: lit ? 1 : 0.12,
            },
            className:
              e.kind === "runs_on"
                ? "[&_path]:!stroke-foreground/60"
                : e.kind === "gateway_of"
                  ? "[&_path]:!stroke-sky-500"
                  : "[&_path]:!stroke-rose-500",
          };
        }),
    [edges, kindOf, related, selectedId, mode],
  );

  // Keep positions the user dragged; everything else follows the layout.
  const moved = React.useRef(new Set<string>());
  const [flowNodes, setFlowNodes, onNodesChange] = useNodesState<AssetRFNode>([]);
  React.useEffect(() => {
    setFlowNodes((prev) => {
      const old = new Map(prev.map((n) => [n.id, n.position]));
      return rfNodes.map((n) => (moved.current.has(n.id) ? { ...n, position: old.get(n.id) ?? n.position } : n));
    });
  }, [rfNodes, setFlowNodes]);

  const [menu, setMenu] = React.useState<MenuState | null>(null);
  const openMenu = (event: MouseEvent | React.MouseEvent, node: AssetNode | null) => {
    if (!onAnalyze) return;
    event.preventDefault();
    const box = (event.target as HTMLElement).closest(".react-flow")?.getBoundingClientRect();
    if (!box) return;
    // Keep the menu inside the map.
    setMenu({
      x: Math.min(event.clientX - box.left, box.width - 220),
      y: Math.min(event.clientY - box.top, box.height - 96),
      node,
    });
  };
  React.useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("click", close);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [menu]);
  const memberCount = (id: string) => edges.filter((e) => e.kind === "member_of" && e.to === id).length;
  const menuItem =
    "block w-full px-3 py-1.5 text-left hover:bg-muted disabled:opacity-50 disabled:hover:bg-transparent";

  const switchMode = (next: LayoutMode) => {
    if (next === mode) return;
    // Dragged positions belong to the layout they were dragged in.
    moved.current.clear();
    setMode(next);
    try {
      window.localStorage.setItem(MODE_KEY, next);
    } catch {
      /* not remembered */
    }
    // Refit once the new positions have been rendered and measured; a single
    // short delay can fire before React Flow has the new node sizes.
    for (const delay of [80, 400]) {
      window.setTimeout(() => void flow.fitView({ padding: 0.15, duration: 300 }), delay);
    }
  };

  return (
    <ReactFlow
      nodes={flowNodes}
      edges={rfEdges}
      onNodesChange={onNodesChange}
      onNodeDragStop={(_, node) => moved.current.add(node.id)}
      nodeTypes={nodeTypes}
      onNodeClick={(_, node) =>
        node.type !== "tier" && node.type !== "frame" && onSelect(node.id === selectedId ? null : node.id)
      }
      onPaneClick={() => onSelect(null)}
      onNodeContextMenu={(event, node) => {
        const target = node.type === "tier" || node.type === "frame" ? undefined : nodes.find((n) => n.id === node.id);
        if (target) openMenu(event, target);
        else event.preventDefault();
      }}
      onPaneContextMenu={(event) => openMenu(event, null)}
      onMoveStart={() => setMenu(null)}
      nodesConnectable={false}
      fitView
      fitViewOptions={{ padding: 0.15 }}
      proOptions={{ hideAttribution: true }}
      minZoom={0.1}
      className="!bg-[#f0f2f7] dark:!bg-neutral-950"
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={16}
        size={1}
        className="text-neutral-400/50 dark:text-neutral-700/60"
      />
      <Panel position="top-left" className="flex overflow-hidden rounded-lg border bg-card text-xs shadow-sm">
        {MODES.map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => switchMode(m)}
            aria-pressed={mode === m}
            className={cn("px-2.5 py-1.5", mode === m ? "bg-primary text-primary-foreground" : "hover:bg-muted")}
          >
            {t(`layout.${m}`)}
          </button>
        ))}
      </Panel>
      {menu && onAnalyze && (
        <div
          role="menu"
          className="absolute z-20 w-52 overflow-hidden rounded-lg border bg-popover py-1 text-popover-foreground text-xs shadow-md"
          style={{ left: menu.x, top: menu.y }}
        >
          {menu.node === null &&
            (paneTargets ?? []).map((target) => (
              <button
                key={target.id}
                type="button"
                role="menuitem"
                className={menuItem}
                onClick={() => onAnalyze(null, target.id)}
              >
                {t("analysis.menuAll", { name: target.label })}
              </button>
            ))}
          {menu.node && isHostNode(menu.node) && (
            <>
              <p className="truncate px-3 py-1 font-medium text-[11px] text-muted-foreground">{menu.node.name}</p>
              <button
                type="button"
                role="menuitem"
                className={menuItem}
                // A machine without an agent sends no alerts to analyse.
                disabled={menu.node.status === "no_agent"}
                onClick={() => menu.node && onAnalyze(menu.node.id)}
              >
                {t("analysis.menuHost")}
              </button>
              {onOpenDetail && (
                <button
                  type="button"
                  role="menuitem"
                  className={menuItem}
                  onClick={() => menu.node && onOpenDetail(menu.node.id)}
                >
                  {t("host.detail")}
                </button>
              )}
            </>
          )}
          {menu.node && !isHostNode(menu.node) && (
            <>
              <p className="truncate px-3 py-1 font-medium text-[11px] text-muted-foreground">{menu.node.name}</p>
              <button
                type="button"
                role="menuitem"
                className={menuItem}
                disabled={memberCount(menu.node.id) === 0}
                onClick={() => menu.node && onAnalyze(menu.node.id)}
              >
                {t("analysis.menuGroup", { count: memberCount(menu.node.id) })}
              </button>
            </>
          )}
        </div>
      )}
      <Controls
        showInteractive={false}
        className="!rounded-lg !border !shadow-sm [&>button]:!border-border [&>button]:!bg-card [&>button:hover]:!bg-accent [&_svg]:!fill-foreground"
      />
      {/* Bottom-left, beside the zoom controls: the detail panel opens on the right. */}
      <MiniMap
        pannable
        zoomable
        position="bottom-left"
        className="!ml-14 !rounded-lg !border !bg-card !shadow-sm"
        maskColor="rgb(148 163 184 / 0.18)"
        nodeStrokeWidth={0}
        nodeBorderRadius={4}
      />
    </ReactFlow>
  );
}
