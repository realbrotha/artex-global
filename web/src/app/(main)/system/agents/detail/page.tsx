"use client";

import * as React from "react";

import { useSearchParams } from "next/navigation";

import { useTranslations } from "next-intl";

import { AgentEditor } from "@/components/agent-editor";
import { DetailHeader } from "@/components/page";
import { Badge } from "@/components/ui/badge";
import { useAgentLabels } from "@/lib/agent-i18n";
import { api } from "@/lib/api";
import type { Agent } from "@/lib/types";

// Deep-link editor page for one agent. The primary flow is the drawer on
// /system/agents; this page reuses the same AgentEditor component full-width so a
// direct URL (or an external link) still opens the editor.
function AgentDetailInner() {
  const searchParams = useSearchParams();
  const key = searchParams.get("key") ?? "";
  const t = useTranslations("agentsPage");
  const tNav = useTranslations("nav");
  const labels = useAgentLabels();
  const [agent, setAgent] = React.useState<Agent | null>(null);

  // 머리 카드에 쓸 이름·배지만 읽는다. 편집기는 따로 읽는다.
  React.useEffect(() => {
    if (!key) return;
    api
      .getAgent(key)
      .then((d) => setAgent(d.agent ?? null))
      .catch(() => setAgent(null));
  }, [key]);

  return (
    <div data-page-fill className="flex min-h-0 flex-1 flex-col gap-4">
      <DetailHeader
        parent={{ label: tNav("item.agents"), href: "/system/agents" }}
        title={agent ? labels.name(agent) : key}
        badges={
          <>
            <span className="font-mono text-muted-foreground text-xs">{key}</span>
            {agent &&
              (agent.builtin ? (
                <Badge variant="secondary">{t("badgeBuiltin")}</Badge>
              ) : (
                <Badge variant="outline">{t("badgeCustom")}</Badge>
              ))}
            {agent && !agent.enabled && (
              <Badge variant="outline" className="text-danger">
                {t("badgeDisabled")}
              </Badge>
            )}
          </>
        }
      />
      <div className="flex min-h-0 flex-1 flex-col rounded-xl border bg-card">
        <AgentEditor agentKey={key} />
      </div>
    </div>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function AgentDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <AgentDetailInner />
    </React.Suspense>
  );
}
