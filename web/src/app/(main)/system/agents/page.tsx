"use client";

import * as React from "react";

import { Bot, PlusIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { AgentEditor } from "@/components/agent-editor";
import { DrawerFooter, ListEmpty, PageHeader, useConfirm } from "@/components/page";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import { useAgentLabels } from "@/lib/agent-i18n";
import { api } from "@/lib/api";
import type { Agent } from "@/lib/types";

// AgentGridCard is one clickable tile opening the agent's editor drawer. Custom
// (non-builtin) agents get a delete button.
function AgentGridCard({ agent, onOpen, onDeleted }: { agent: Agent; onOpen: () => void; onDeleted: () => void }) {
  const t = useTranslations("agentsPage");
  const labels = useAgentLabels();
  const confirm = useConfirm();
  async function del() {
    if (
      !(await confirm({
        title: t("deleteTitle", { name: agent.name }),
        description: t("deleteDesc"),
        confirmLabel: t("delete"),
        destructive: true,
      }))
    )
      return;
    try {
      await api.deleteAgent(agent.key);
      toast.success(t("deleted", { name: agent.name }));
      onDeleted();
    } catch (e) {
      toast.error(t("deleteFailed", { msg: (e as Error).message }));
    }
  }
  return (
    <div className="group relative flex flex-col gap-2 rounded-xl border bg-card p-4 transition-colors hover:border-primary/50">
      <button type="button" onClick={onOpen} className="flex flex-col gap-2 text-left">
        <div className="flex flex-wrap items-center gap-2">
          <Bot className="size-4 text-muted-foreground" />
          <span className="font-medium text-sm">{labels.name(agent)}</span>
          <span className="font-mono text-muted-foreground text-xs">{agent.key}</span>
          {agent.builtin ? (
            <Badge variant="secondary">{t("badgeBuiltin")}</Badge>
          ) : (
            <Badge variant="outline">{t("badgeCustom")}</Badge>
          )}
          {!agent.enabled && (
            <Badge variant="outline" className="text-danger">
              {t("badgeDisabled")}
            </Badge>
          )}
        </div>
        {/* labels.description 은 string 을 돌려주므로(빈 설명은 "") || 로 폴백 문구를 붙인다. */}
        <p className="line-clamp-2 min-h-8 text-muted-foreground text-xs">
          {labels.description(agent) || t("noDescription")}
        </p>
        <div className="flex flex-wrap gap-1.5 text-muted-foreground text-xs">
          <span className="rounded border px-1.5 py-0.5">MCP {agent.mcp_count ?? 0}</span>
          <span className="rounded border px-1.5 py-0.5">Skill {agent.skill_count ?? 0}</span>
          <span className="rounded border px-1.5 py-0.5">
            {t("toolLabel")} {agent.tool_count ?? 0}
          </span>
        </div>
      </button>
      {!agent.builtin && (
        <Button
          variant="ghost"
          size="icon-xs"
          aria-label={t("delete")}
          title={t("delete")}
          onClick={del}
          className="absolute top-2 right-2 text-muted-foreground opacity-0 transition-opacity hover:text-danger group-hover:opacity-100"
        >
          <Trash2Icon className="size-3.5" />
        </Button>
      )}
    </div>
  );
}

// 사용자 정의 에이전트 만들기 드로어.
function CreateAgentSheet({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (key: string) => void;
}) {
  const t = useTranslations("agentsPage");
  const [key, setKey] = React.useState("");
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function create() {
    setBusy(true);
    try {
      const a = await api.createAgent(key.trim(), name.trim(), description.trim());
      toast.success(t("created", { name: a.name }));
      onOpenChange(false);
      setKey("");
      setName("");
      setDescription("");
      onCreated(a.key);
    } catch (e) {
      toast.error(t("createFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  const keyOk = /^[a-z][a-z0-9_]*$/.test(key.trim());
  const canCreate = keyOk && name.trim().length > 0 && !busy;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" size="sm">
        <SheetHeader>
          <SheetTitle>{t("createTitle")}</SheetTitle>
          <SheetDescription>{t("createDesc")}</SheetDescription>
        </SheetHeader>
        <div className="grid min-h-0 flex-1 content-start gap-4 overflow-y-auto px-4">
          <div className="grid gap-1.5">
            <Label htmlFor="agent-key">Key</Label>
            <Input
              id="agent-key"
              placeholder={t("keyPlaceholder")}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              className="font-mono"
            />
            {key.length > 0 && !keyOk && <span className="text-danger text-xs">{t("keyError")}</span>}
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="agent-name">{t("nameLabel")}</Label>
            <Input
              id="agent-name"
              placeholder={t("namePlaceholder")}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="agent-desc">{t("descLabel")}</Label>
            <Textarea
              id="agent-desc"
              placeholder={t("descPlaceholder")}
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
        </div>
        <DrawerFooter
          onCancel={() => onOpenChange(false)}
          confirmLabel={t("create")}
          onConfirm={create}
          confirmDisabled={!canCreate}
          pending={busy}
        />
      </SheetContent>
    </Sheet>
  );
}

export default function AgentsPage() {
  const t = useTranslations("agentsPage");
  const labels = useAgentLabels();
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [editKey, setEditKey] = React.useState<string | null>(null);
  const [createOpen, setCreateOpen] = React.useState(false);

  const reload = React.useCallback(() => {
    api
      .agents()
      .then(setAgents)
      .catch(() => setAgents([]));
  }, []);
  React.useEffect(() => {
    reload();
  }, [reload]);

  const editing = agents.find((a) => a.key === editKey) ?? null;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <PlusIcon /> {t("new")}
          </Button>
        }
      >
        <span className="text-muted-foreground text-sm tabular-nums">{t("countTotal", { count: agents.length })}</span>
      </PageHeader>

      {agents.length === 0 ? (
        <ListEmpty title={t("empty")} />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {agents.map((a) => (
            <AgentGridCard key={a.key} agent={a} onOpen={() => setEditKey(a.key)} onDeleted={reload} />
          ))}
        </div>
      )}

      <CreateAgentSheet
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(key) => {
          reload();
          setEditKey(key);
        }}
      />

      <Sheet open={!!editing} onOpenChange={(o) => !o && setEditKey(null)}>
        <SheetContent side="right" size="md">
          {editing && (
            <>
              <SheetHeader className="px-4">
                <SheetTitle className="flex items-center gap-2">
                  {labels.name(editing)}
                  <span className="font-mono text-muted-foreground text-xs">{editing.key}</span>
                  {!editing.builtin && <Badge variant="outline">{t("badgeCustom")}</Badge>}
                </SheetTitle>
                <SheetDescription>{labels.description(editing) || t("editorDescFallback")}</SheetDescription>
              </SheetHeader>
              <AgentEditor agentKey={editing.key} onSaved={reload} />
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
