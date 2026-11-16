import { http } from "@/lib/api";

export interface SecurityLogStream {
  index: string;
  sourcetype: string;
  kind: "audit" | "alert";
  label?: string;
  asset?: string;
}

export interface SecuritySourceConfig {
  base_url: string;
  streams?: SecurityLogStream[];
  // Kept for connections saved before multi-stream support.
  index?: string;
  audit_sourcetype?: string;
  alert_sourcetype?: string;
  correlation_field: string;
  action_field: string;
  tls_fingerprint: string;
}

export interface SecuritySource {
  id: string;
  name: string;
  revision: number;
  config: SecuritySourceConfig;
  enabled: boolean;
  credential_set: boolean;
  updated_at: string;
}

export function securitySourceSourcetypes(source?: SecuritySource): string[] {
  const config = source?.config;
  const values = config?.streams?.length
    ? config.streams.map((stream) => stream.sourcetype)
    : [config?.audit_sourcetype, config?.alert_sourcetype];
  return [...new Set(values.filter((value): value is string => Boolean(value)))];
}

export interface SecuritySourceInput {
  name: string;
  config: SecuritySourceConfig;
  enabled: boolean;
  expected_revision: number;
  username?: string;
  password?: string;
  token?: string;
}

export interface SecurityStreamTest {
  ok: boolean;
  detail: string;
  index: string;
  sourcetype: string;
  kind: "audit" | "alert";
  searchable: boolean;
  has_recent_events: boolean;
}

export const securityApi = {
  sources: () => http<{ sources: SecuritySource[] }>("/purple/sources"),
  indexes: (id: string) => http<{ indexes: string[] }>(`/purple/sources/${encodeURIComponent(id)}/indexes`),
  testStream: (id: string, streamIndex: number) =>
    http<SecurityStreamTest>(`/purple/sources/${encodeURIComponent(id)}/streams/${streamIndex}/test`, {
      method: "POST",
    }),
  saveSource: (id: string | null, input: SecuritySourceInput) =>
    http<SecuritySource>(id ? `/purple/sources/${encodeURIComponent(id)}` : "/purple/sources", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(input),
    }),
  testSource: (id: string) =>
    http<{ ok: boolean; detail: string }>(`/purple/sources/${encodeURIComponent(id)}/test`, { method: "POST" }),
  deleteSource: (id: string, expectedRevision: number) =>
    http<{ deleted: string }>(`/purple/sources/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: JSON.stringify({ expected_revision: expectedRevision }),
    }),
};

export function downloadSecurityJSON(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
