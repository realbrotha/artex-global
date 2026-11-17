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
// gateway_of: a bastion and the cluster whose private network it fronts.
export type AssetEdgeKind = "runs_on" | "member_of" | "gateway_of";

export interface AssetNode {
  id: string;
  kind: AssetKind;
  name: string;
  // Agent status from the manager, or "no_agent" for a machine known only
  // through its hypervisor. Group nodes carry no status.
  status?: string;
  ip?: string;
  // First public IPv4 on a host interface and every host-level address,
  // from the agent inventory. Absent when the inventory could not be read.
  public_ip?: string;
  addrs?: AssetAddr[];
  os?: string;
  groups?: string[];
  roles?: string[];
  services?: string[];
  virt?: string;
  last_seen?: string;
  checked?: string;
  members?: number;
  // Latest config-check counts; absent when the host has no check result.
  checks?: AssetChecks;
  // Case candidates involving this host (known activity excluded) and the
  // most severe of them.
  cases?: number;
  case_sev?: CaseSeverity;
}

export interface AssetAddr {
  ip: string;
  iface?: string;
  public?: boolean;
}

export type CaseSeverity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface SiemCaseEvent {
  t: string;
  host: string;
  rule: string;
  level: number;
  actor: string;
  src: string;
  object: string;
  desc: string;
}

// One case candidate: one detection criterion on one subject.
export interface SiemCase {
  id: string;
  pattern: string;
  score: number;
  entity: string;
  hosts: string[];
  first: string;
  last: string;
  n: number;
  attack: string[];
  summary: string;
  // Registry reason when the case is approved normal activity.
  known?: string;
  near: string[];
  severity: CaseSeverity;
  sev_basis: string;
  criterion: string;
  title?: string;
  actor: string;
  // Present only on a single-case fetch.
  timeline?: SiemCaseEvent[];
  verdict?: CaseVerdict;
}

// LLM verdict on a case. stale: the case has newer activity than the verdict
// judged, or the verdict is past its age limit.
export interface CaseVerdict {
  verdict: "breach" | "suspicious" | "attempt" | "normal" | "false_positive";
  title: string;
  explain: string;
  evidence: string[];
  severity: CaseSeverity;
  adjust?: string;
  response?: string[];
  model: string;
  judged_at: string;
  stale: boolean;
}

export interface CaseSource {
  id: string;
  name: string;
  cases_at: string | null;
  error: string;
  meta: { alerts: number; capped: boolean; window_days: number; rules: number; seen_note: string };
  cases: SiemCase[];
}

export interface AssetChecks {
  fail: number;
  review: number;
  error: number;
  pass: number;
  na: number;
  // Failed or review results covered by the accepted-risk registry; not
  // included in fail or review.
  accepted: number;
}

export interface Acceptance {
  reason: string;
  approved_by: string;
  until?: string;
  host: string;
}

export interface AssetIssue {
  code: string;
  result: "fail" | "review" | "error";
  sev?: string;
  std?: string;
  title?: string;
  ev?: string;
  asset?: string;
  // Registry code when it differs from code ("CIS 6.3.1").
  key?: string;
  accepted?: Acceptance;
}

export interface AcceptedRisk {
  code: string;
  host: string;
  reason: string;
  approved_by: string;
  until: string;
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
  // Why interface addresses are missing, when they are.
  addr_note?: string;
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
  checks: (id: string, node: string) =>
    http<{ issues: AssetIssue[] }>(`${base}/${encodeURIComponent(id)}/checks?node=${encodeURIComponent(node)}`),
  cases: () => http<{ sources: CaseSource[] }>("/defensive/cases"),
  caseDetail: (id: string, caseId: string) =>
    http<SiemCase>(`${base}/${encodeURIComponent(id)}/cases/${encodeURIComponent(caseId)}`),
  judgeCase: (id: string, caseId: string) =>
    http<CaseVerdict>(`${base}/${encodeURIComponent(id)}/cases/${encodeURIComponent(caseId)}/judge`, {
      method: "POST",
    }),
  acceptedRisks: () => http<{ risks: AcceptedRisk[] }>("/defensive/accepted-risks"),
  replaceAcceptedRisks: (tsv: string) =>
    http<{ risks: AcceptedRisk[] }>("/defensive/accepted-risks", { method: "PUT", body: JSON.stringify({ tsv }) }),
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

// Whether a case names this host. Cases carry FQDNs; node ids use the short
// lowercase host name ("host:web01").
export function caseInvolvesHost(c: SiemCase, nodeId: string): boolean {
  const short = nodeId.replace(/^host:/, "");
  return c.hosts.some((h) => h.split(".")[0].toLowerCase() === short);
}

export function hostDetailUrl(sourceId: string, nodeId: string): string {
  return `/defensive/assets/host?source=${encodeURIComponent(sourceId)}&node=${encodeURIComponent(nodeId)}`;
}

export interface AnalysisStep {
  status: "" | "running" | "done" | "failed";
  ms?: number;
}

export type AnalysisCase = SiemCase & {
  // Verdict run inside this analysis.
  judge?: "pending" | "running" | "done" | "failed";
  judge_error?: string;
  judge_ms?: number;
};

// A manual analysis of chosen hosts; polled while it runs.
export interface Analysis {
  id: string;
  label: string;
  hosts: string[];
  days: number;
  state: "collecting" | "extracting" | "ready" | "judging" | "done" | "failed" | "stopped";
  error?: string;
  collect: AnalysisStep;
  alerts: number;
  capped: boolean;
  rules: number;
  extract: AnalysisStep;
  patterns: Record<string, number>;
  cases: AnalysisCase[];
  judge_done: number;
  judge_total: number;
  model?: string;
}

const analysisBase = (id: string) => `${base}/${encodeURIComponent(id)}/analyses`;

export const analysisApi = {
  // An empty host list analyses every host of the connection.
  start: (sourceId: string, label: string, hosts: string[]) =>
    http<Analysis>(analysisBase(sourceId), { method: "POST", body: JSON.stringify({ label, hosts }) }),
  get: (sourceId: string, id: string) => http<Analysis>(`${analysisBase(sourceId)}/${encodeURIComponent(id)}`),
  judge: (sourceId: string, id: string) =>
    http<Analysis>(`${analysisBase(sourceId)}/${encodeURIComponent(id)}/judge`, { method: "POST" }),
  stop: (sourceId: string, id: string) =>
    http<Analysis>(`${analysisBase(sourceId)}/${encodeURIComponent(id)}/stop`, { method: "POST" }),
};
