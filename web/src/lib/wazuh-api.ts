import { http } from "@/lib/api";

export interface WazuhConfig {
  manager_url: string;
  indexer_url: string;
  tls_fingerprint: string;
  tls_skip_verify: boolean;
}

export interface WazuhSource {
  id: string;
  name: string;
  revision: number;
  config: WazuhConfig;
  enabled: boolean;
  credential_set: boolean;
  synced_at: string | null;
  sync_error: string;
  updated_at: string;
}

export interface WazuhSourceInput {
  name: string;
  config: WazuhConfig;
  enabled: boolean;
  expected_revision: number;
  manager_user?: string;
  manager_password?: string;
  indexer_user?: string;
  indexer_password?: string;
}

export type AssetKind = "baremetal" | "vm" | "unknown" | "k8s_cluster" | "openstack";
export type AssetEdgeKind = "runs_on" | "member_of";

export interface AssetNode {
  id: string;
  kind: AssetKind;
  name: string;
  // Agent status from the manager, or "no_agent" for a machine known only
  // through its hypervisor. Group nodes carry no status.
  status?: string;
  ip?: string;
  os?: string;
  groups?: string[];
  roles?: string[];
  services?: string[];
  virt?: string;
  last_seen?: string;
  checked?: string;
  members?: number;
}

export interface AssetEdge {
  from: string;
  to: string;
  kind: AssetEdgeKind;
}

export interface AssetSource {
  id: string;
  name: string;
  synced_at: string | null;
  sync_error: string;
  indexer: boolean;
  nodes: AssetNode[];
  edges: AssetEdge[];
}

const base = "/defensive/wazuh";

export const wazuhApi = {
  sources: () => http<{ sources: WazuhSource[] }>(base),
  save: (id: string | null, input: WazuhSourceInput) =>
    http<WazuhSource>(id ? `${base}/${encodeURIComponent(id)}` : base, {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(input),
    }),
  remove: (id: string, expectedRevision: number) =>
    http<{ deleted: string }>(`${base}/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: JSON.stringify({ expected_revision: expectedRevision }),
    }),
  test: (id: string) =>
    http<{ ok: boolean; agents: number; indexer: boolean }>(`${base}/${encodeURIComponent(id)}/test`, {
      method: "POST",
    }),
  sync: (id: string) => http<WazuhSource>(`${base}/${encodeURIComponent(id)}/sync`, { method: "POST" }),
  assets: () => http<{ sources: AssetSource[] }>("/defensive/assets"),
};

export type AssetStatusGroup = "ok" | "down" | "missing" | "none";

// Collapses manager statuses into the three states the UI distinguishes.
export function assetStatusGroup(node: AssetNode): AssetStatusGroup {
  if (node.kind === "k8s_cluster" || node.kind === "openstack") return "none";
  if (node.status === "active") return "ok";
  if (node.status === "no_agent") return "missing";
  return "down";
}

export function isHostNode(node: AssetNode): boolean {
  return node.kind === "baremetal" || node.kind === "vm" || node.kind === "unknown";
}
