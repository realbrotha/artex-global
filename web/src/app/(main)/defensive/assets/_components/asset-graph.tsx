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
  Position,
  ReactFlow,
  ReactFlowProvider,
  type Edge as RFEdge,
  type Node as RFNode,
  useNodesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { BoxIcon, CircleHelpIcon, type LucideIcon, ServerIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { siKubernetes, siOpenstack } from "simple-icons";

import { SimpleIcon } from "@/components/simple-icon";
import { cn } from "@/lib/utils";
import { type AssetEdge, type AssetNode, assetStatusGroup, isHostNode } from "@/lib/wazuh-api";

import { layoutAssets, NODE_H, NODE_W } from "./asset-layout";

type AssetNodeData = { node: AssetNode; dim: boolean; active: boolean; subtitle: string; w?: number; h?: number };
type AssetRFNode = RFNode<AssetNodeData, "asset" | "cluster">;

const hostIcon: Record<string, LucideIcon> = { baremetal: ServerIcon, vm: BoxIcon, unknown: CircleHelpIcon };

const statusDot: Record<string, string> = {
  ok: "bg-emerald-500",
  down: "bg-red-500",
  missing: "bg-amber-500",
};

function AssetNodeCard({ data }: NodeProps<AssetRFNode>) {
  const { node, dim, active, subtitle } = data;
  const group = assetStatusGroup(node);
  const isGroup = !isHostNode(node);
  const Icon = hostIcon[node.kind];
  return (
    <div
      className={cn(
        "relative flex items-center gap-2 border bg-card px-2 text-left shadow-xs transition-opacity",
        isGroup || node.kind === "vm" ? "rounded-full" : "rounded-md",
        node.kind === "baremetal" && "border-foreground/40",
        group === "missing" && "border-amber-500 border-dashed",
        active && "ring-2 ring-primary",
        dim && "opacity-25",
      )}
      style={{ width: NODE_W, height: NODE_H }}
    >
      <Handle id="t-in" type="target" position={Position.Top} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="t-out" type="source" position={Position.Top} className="!size-1 !border-0 !bg-transparent" />
      <span
        className={cn(
          "flex size-9 shrink-0 items-center justify-center",
          isGroup || node.kind === "vm" ? "rounded-full" : "rounded-md",
          node.kind === "openstack" && "bg-rose-500/10",
          isHostNode(node) && "bg-muted",
        )}
      >
        {node.kind === "openstack" ? (
          <SimpleIcon icon={siOpenstack} className="size-5 fill-rose-600 dark:fill-rose-400" />
        ) : (
          <Icon className="size-4.5 text-muted-foreground" />
        )}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate font-medium text-xs">{node.name}</span>
        <span className="block truncate text-[10px] text-muted-foreground">{subtitle}</span>
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
function ClusterBox({ data }: NodeProps<AssetRFNode>) {
  const { node, dim, active, subtitle, w, h } = data;
  return (
    <div
      className={cn(
        "rounded-xl border border-sky-500/40 bg-sky-500/5 transition-opacity",
        active && "ring-2 ring-primary",
        dim && "opacity-25",
      )}
      style={{ width: w, height: h }}
    >
      <div className="flex h-10 items-center gap-2 px-3.5">
        <SimpleIcon icon={siKubernetes} className="size-4 shrink-0 fill-sky-600 dark:fill-sky-400" />
        <span className="truncate font-medium text-xs">{node.name}</span>
        <span className="shrink-0 text-[10px] text-muted-foreground">{subtitle}</span>
      </div>
    </div>
  );
}

const nodeTypes = { asset: AssetNodeCard, cluster: ClusterBox };

interface AssetGraphProps {
  readonly nodes: AssetNode[];
  readonly edges: AssetEdge[];
  readonly selectedId: string | null;
  readonly onSelect: (id: string | null) => void;
}

export function AssetGraph(props: AssetGraphProps) {
  return (
    <ReactFlowProvider>
      <AssetGraphInner {...props} />
    </ReactFlowProvider>
  );
}

function AssetGraphInner({ nodes, edges, selectedId, onSelect }: AssetGraphProps) {
  const t = useTranslations("protectedAssets");

  const positions = React.useMemo(() => layoutAssets(nodes, edges), [nodes, edges]);

  const related = React.useMemo(() => {
    if (!selectedId) return null;
    const set = new Set([selectedId]);
    for (const e of edges) {
      if (e.from === selectedId) set.add(e.to);
      if (e.to === selectedId) set.add(e.from);
    }
    return set;
  }, [edges, selectedId]);

  const rfNodes = React.useMemo<AssetRFNode[]>(
    () =>
      nodes.map((node) => {
        const subtitle = isHostNode(node)
          ? [t(`kind.${node.kind}`), node.roles?.join(", ")].filter(Boolean).join(" · ")
          : t("memberCount", { count: node.members ?? 0 });
        const at = positions.get(node.id) ?? { x: 0, y: 0 };
        const isBox = node.kind === "k8s_cluster";
        return {
          id: node.id,
          type: isBox ? "cluster" : "asset",
          position: { x: at.x, y: at.y },
          // Boxes stay put: their members are separate nodes laid out inside.
          draggable: !isBox,
          zIndex: isBox ? -1 : 0,
          data: {
            node,
            subtitle,
            w: at.w,
            h: at.h,
            active: node.id === selectedId,
            dim: related !== null && !related.has(node.id),
          },
        };
      }),
    [nodes, positions, related, selectedId, t],
  );

  const kindOf = React.useMemo(() => new Map(nodes.map((n) => [n.id, n.kind])), [nodes]);

  const rfEdges = React.useMemo<RFEdge[]>(
    () =>
      edges
        // Cluster membership is shown by containment, not by an edge.
        .filter((e) => kindOf.has(e.from) && kindOf.has(e.to) && kindOf.get(e.to) !== "k8s_cluster")
        .map((e) => {
          const lit = related === null || e.from === selectedId || e.to === selectedId;
          return {
            id: `${e.kind}:${e.from}>${e.to}`,
            source: e.from,
            target: e.to,
            sourceHandle: "b-out",
            targetHandle: "t-in",
            style: {
              strokeWidth: e.kind === "runs_on" ? 1.5 : 1,
              strokeDasharray: e.kind === "member_of" ? "5 4" : undefined,
              opacity: lit ? 1 : 0.12,
            },
            className: e.kind === "runs_on" ? "[&_path]:!stroke-foreground/60" : "[&_path]:!stroke-rose-500",
          };
        }),
    [edges, kindOf, related, selectedId],
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

  return (
    <ReactFlow
      nodes={flowNodes}
      edges={rfEdges}
      onNodesChange={onNodesChange}
      onNodeDragStop={(_, node) => moved.current.add(node.id)}
      nodeTypes={nodeTypes}
      onNodeClick={(_, node) => onSelect(node.id === selectedId ? null : node.id)}
      onPaneClick={() => onSelect(null)}
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
      <Controls
        showInteractive={false}
        className="!rounded-lg !border !shadow-sm [&>button]:!border-border [&>button]:!bg-card [&>button:hover]:!bg-accent [&_svg]:!fill-foreground"
      />
      <MiniMap
        pannable
        zoomable
        className="!rounded-lg !border !bg-card !shadow-sm"
        maskColor="rgb(148 163 184 / 0.18)"
        nodeStrokeWidth={0}
        nodeBorderRadius={4}
      />
    </ReactFlow>
  );
}
