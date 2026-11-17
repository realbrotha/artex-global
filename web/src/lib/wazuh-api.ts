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
  // high, medium or low, as the model rated its own certainty.
  confidence?: "high" | "medium" | "low";
  // single: one pass · debate: two opposing reviews and an arbiter ·
  // fallback: nothing valid came back, confirmed conservatively as suspicious.
  // human: a person's correction, which the automatic judging keeps.
  method?: "single" | "debate" | "fallback" | "human";
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
  correctCase: (id: string, caseId: string, verdict: CaseVerdict["verdict"], reason: string) =>
    http<CaseVerdict>(`${base}/${encodeURIComponent(id)}/cases/${encodeURIComponent(caseId)}/correct`, {
      method: "POST",
      body: JSON.stringify({ verdict, reason }),
    }),
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
  // Collect detail: hosts with a config-check result, hosts that produced
  // alerts, the period the alerts span and the rules that fired most.
  checked_hosts: number;
  alert_hosts: number;
  alert_from?: string;
  alert_to?: string;
  top_rules: { id: string; desc: string; level: number; count: number }[];
  // Alerts per host, most first.
  alert_by_host?: { host: string; count: number }[];
  // Alerts written to the run history; -1 while they are being written.
  alerts_stored?: number;
  // Stored runs only: each case's alert timeline by case id.
  timelines?: Record<string, SiemCaseEvent[] | null>;
  rules: number;
  // Why first-seen logins could not be used, when they could not.
  seen_note?: string;
  extract: AnalysisStep;
  patterns: Record<string, number>;
  cases: AnalysisCase[];
  judge_done: number;
  judge_total: number;
  model?: string;
  trigger?: "manual" | "schedule";
  // Why judging did not run or stopped short.
  judge_note?: string;
  debated?: number;
  fallback?: number;
  // Cases left for the next run by the per-run limit.
  deferred?: number;
}

// Feedback on the automatic judging: per criterion, what people corrected,
// and the signals worth acting on.
export interface CriterionFeedback {
  criterion: string;
  title: string;
  cases: number;
  verdicts: Partial<Record<CaseVerdict["verdict"], number>>;
  judgements: number;
  debated: number;
  fallback: number;
  corrected: number;
}

export interface FeedbackSignal {
  kind: "false_positive_heavy" | "normal_repeat" | "unstable" | "corrected";
  criterion: string;
  title: string;
  case_key?: string;
  count: number;
  of: number;
}

export interface Correction {
  id: number;
  case_key: string;
  criterion: string;
  actor: string;
  summary: string;
  from: string;
  to: CaseVerdict["verdict"];
  reason: string;
  created_at: string;
}

export interface FeedbackSource {
  id: string;
  name: string;
  criteria: CriterionFeedback[];
  signals: FeedbackSignal[];
  corrections: Correction[];
  // Current verdicts by how they were reached.
  methods: Record<string, number>;
}

export const feedbackApi = {
  get: () => http<{ sources: FeedbackSource[]; window_days: number }>("/defensive/feedback"),
};

// When the analysis runs by itself, and how it judges.
export interface SiemSchedule {
  enabled: boolean;
  mode: "interval" | "daily";
  interval_minutes: number;
  times: string[];
  // 0 = Sunday .. 6 = Saturday; empty = every day.
  weekdays: number[];
  auto_judge: boolean;
  judge_limit: number;
  debate: boolean;
}

export interface ScheduleState {
  schedule: SiemSchedule;
  last_run?: string | null;
  next_run?: string;
}

export const scheduleApi = {
  get: () => http<ScheduleState>("/defensive/schedule"),
  save: (s: SiemSchedule) => http<ScheduleState>("/defensive/schedule", { method: "PUT", body: JSON.stringify(s) }),
  runNow: () => http<{ started: number }>("/defensive/schedule/run", { method: "POST" }),
};

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

// One stored manual analysis. detail is present on a single-run fetch.
export interface AnalysisRun {
  id: string;
  source_name: string;
  label: string;
  state: Analysis["state"];
  started_at: string;
  updated_at: string;
  hosts: number;
  alerts: number;
  cases: number;
  judged: number;
  model: string;
  detail?: Analysis;
}

// One request to the model inside a judgment: what was sent and what came
// back. A later attempt's prompt lists the rules the previous answer broke.
export interface JudgeAttempt {
  // analyst, threat, benign or arbiter; absent on records made before roles.
  role?: "analyst" | "threat" | "benign" | "arbiter";
  // System prompt of a role other than the analyst's.
  system?: string;
  prompt: string;
  response: string;
  error?: string;
  ms: number;
}

// One LLM judgment of a case candidate. run_id is "" when it was asked for
// outside a manual analysis. Prompts are present on a single fetch.
export interface Judgement {
  id: number;
  run_id: string;
  case_key: string;
  case: SiemCase;
  model: string;
  system_prompt?: string;
  attempts?: JudgeAttempt[];
  tries: number;
  verdict?: Omit<CaseVerdict, "model" | "judged_at" | "stale">;
  // Why the case went to a debate or a fallback.
  reason?: string;
  error?: string;
  ms: number;
  judged_at: string;
}

// One alert a run collected, as it read it.
export interface RunAlert {
  seq: number;
  t: string;
  host: string;
  rule: string;
  level: number;
  desc: string;
  actor: string;
  src: string;
  object: string;
  full_log: string;
}

export const historyApi = {
  alerts: (runId: string, f: { rule?: string; host?: string; q?: string; offset?: number; limit?: number }) => {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(f)) {
      if (value !== undefined && value !== "") params.set(key, String(value));
    }
    return http<{ total: number; alerts: RunAlert[] }>(
      `/defensive/analysis-runs/${encodeURIComponent(runId)}/alerts?${params}`,
    );
  },
  runs: () => http<{ runs: AnalysisRun[] }>("/defensive/analysis-runs"),
  run: (id: string) =>
    // latest: the newest recorded judgment of each case key, from any run or screen.
    http<{ run: AnalysisRun; judgements: Judgement[]; latest: Record<string, Judgement> }>(
      `/defensive/analysis-runs/${encodeURIComponent(id)}`,
    ),
  judgements: () => http<{ judgements: Judgement[] }>("/defensive/judgements"),
  judgement: (id: number) => http<Judgement>(`/defensive/judgements/${id}`),
};

// One config-check item across every host of a connection. A host is in at
// most one of the four lists.
export interface CheckSummary {
  code: string;
  std?: string;
  sev?: string;
  title?: string;
  fail: string[];
  review: string[];
  error: string[];
  accepted: string[];
}

export interface PostureSource {
  id: string;
  name: string;
  synced_at: string | null;
  // Hosts that have a check result.
  hosts: number;
  checks: CheckSummary[];
}

export const postureApi = {
  list: () => http<{ sources: PostureSource[] }>("/defensive/posture"),
};
