"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowRightIcon, ChevronDownIcon, PencilIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import { type SecuritySource, securityApi } from "@/lib/security-api";
import { type AssetSource, isHostNode, type WazuhSource, wazuhApi } from "@/lib/wazuh-api";

import { WazuhConnectionSheet } from "./_components/wazuh-connection-sheet";

type SyncStatus = Awaited<ReturnType<typeof api.ssStatus>>;

const SOURCES_URL = "/defensive/sources";
const SYNC_URL = "/function/sync";

function Section({
  title,
  description,
  action,
  children,
}: {
  readonly title: string;
  readonly description: string;
  // Page controls, in the first section's header rather than on a row of their own.
  readonly action?: React.ReactNode;
  readonly children: React.ReactNode;
}) {
  return (
    <section className="grid grid-cols-1 gap-2">
      <div className="flex items-end gap-3">
        <div className="min-w-0 flex-1">
          <h2 className="font-medium text-sm">{title}</h2>
          <p className="text-muted-foreground text-xs">{description}</p>
        </div>
        {action}
      </div>
      <div className="grid grid-cols-1 divide-y rounded-lg border">{children}</div>
    </section>
  );
}

// One row for a connection kind that has nothing connected yet.
function EmptyRow({ text, action, href }: { readonly text: string; readonly action: string; readonly href?: string }) {
  return (
    <div className="flex flex-wrap items-center gap-3 px-3 py-3">
      <span className="min-w-0 flex-1 text-muted-foreground text-sm">{text}</span>
      {href && (
        <Button asChild size="sm" variant="outline">
          <Link href={href}>{action}</Link>
        </Button>
      )}
    </div>
  );
}

// Every external system the console reads from, on one screen: what is
// connected, whether it works, and when it last synced.
export default function ConnectionsPage() {
  const t = useTranslations("connections");
  const tw = useTranslations("protectedAssets.connection");
  const [wazuh, setWazuh] = React.useState<WazuhSource[] | null>(null);
  const [assets, setAssets] = React.useState<AssetSource[]>([]);
  const [logs, setLogs] = React.useState<SecuritySource[] | null>(null);
  const [sync, setSync] = React.useState<SyncStatus | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState<string | null>(null);
  const [sheet, setSheet] = React.useState<{ source: WazuhSource | null } | null>(null);

  const load = React.useCallback(async () => {
    // Each kind loads on its own so one failing backend does not blank the rest.
    const [w, a, l, s] = await Promise.allSettled([
      wazuhApi.sources(),
      wazuhApi.assets(),
      securityApi.sources(),
      api.ssStatus(),
    ]);
    setWazuh(w.status === "fulfilled" ? w.value.sources : []);
    setAssets(a.status === "fulfilled" ? a.value.sources : []);
    setLogs(l.status === "fulfilled" ? l.value.sources : []);
    setSync(s.status === "fulfilled" ? s.value : null);
    const failed = [w, l].find((r) => r.status === "rejected");
    setError(failed?.status === "rejected" && failed.reason instanceof Error ? failed.reason.message : "");
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const run = async (key: string, action: () => Promise<void>) => {
    setBusy(key);
    try {
      await action();
    } catch (e) {
      toast.error(e instanceof Error && e.message ? e.message : tw("failed"));
    } finally {
      setBusy(null);
    }
  };

  const hostCount = (id: string) => assets.find((s) => s.id === id)?.nodes.filter(isHostNode).length ?? 0;
  const addrNote = (id: string) => assets.find((s) => s.id === id)?.addr_note ?? "";
  const syncReady = Boolean(sync?.exists && sync.configured && sync.enabled);

  return (
    <div className="flex flex-1 flex-col gap-3">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Section
        title={t("wazuh.title")}
        description={t("wazuh.description")}
        action={
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="xs">
                <PlusIcon />
                {t("add")}
                <ChevronDownIcon />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={() => setSheet({ source: null })}>{t("wazuh.title")}</DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link href={SOURCES_URL}>{t("logs.title")}</Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link href={SYNC_URL}>{t("sync.title")}</Link>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        }
      >
        {wazuh === null && <Skeleton className="m-3 h-10" />}
        {wazuh?.length === 0 && <EmptyRow text={t("none")} action="" />}
        {wazuh?.map((source) => (
          <div key={source.id} className="grid grid-cols-1 gap-1.5 px-3 py-3">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
              <span className="font-medium text-sm">{source.name}</span>
              {!source.enabled ? (
                <Badge variant="outline">{tw("disabled")}</Badge>
              ) : source.sync_error ? (
                <Badge variant="destructive">{tw("statusFailed")}</Badge>
              ) : source.synced_at ? (
                <Badge variant="secondary">{tw("statusOk")}</Badge>
              ) : (
                <Badge variant="outline">{tw("statusPending")}</Badge>
              )}
              <span className="text-muted-foreground text-xs">
                {[
                  source.config.indexer_url ? "manager · indexer" : "manager",
                  t("wazuh.hosts", { count: hostCount(source.id) }),
                  source.synced_at && t("syncedAt", { when: new Date(source.synced_at).toLocaleString() }),
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
              <span className="ml-auto flex flex-wrap gap-1.5">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy !== null}
                  onClick={() =>
                    run(`test:${source.id}`, async () => {
                      const result = await wazuhApi.test(source.id);
                      toast.success(tw("testOk", { count: result.agents }));
                    })
                  }
                >
                  {busy === `test:${source.id}` && <Spinner />}
                  {tw("test")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy !== null}
                  onClick={() =>
                    run(`sync:${source.id}`, async () => {
                      await wazuhApi.sync(source.id);
                      toast.success(tw("synced"));
                      await load();
                    })
                  }
                >
                  {busy === `sync:${source.id}` ? <Spinner /> : <RefreshCwIcon />}
                  {tw("sync")}
                </Button>
                <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => setSheet({ source })}>
                  <PencilIcon />
                  {tw("edit")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy !== null}
                  aria-label={tw("delete")}
                  onClick={() =>
                    run(`remove:${source.id}`, async () => {
                      if (!window.confirm(tw("confirmDelete", { name: source.name }))) return;
                      await wazuhApi.remove(source.id, source.revision);
                      toast.success(tw("deleted"));
                      await load();
                    })
                  }
                >
                  <Trash2Icon />
                </Button>
              </span>
            </div>
            <p className="truncate font-mono text-muted-foreground text-xs">{source.config.manager_url}</p>
            {source.sync_error && <p className="break-words text-destructive text-xs">{source.sync_error}</p>}
            {addrNote(source.id) && (
              <p className="break-words text-amber-600 text-xs dark:text-amber-400">
                {t("wazuh.addrNote", { reason: addrNote(source.id) })}
              </p>
            )}
          </div>
        ))}
        <div className="px-3 py-2">
          <Button size="sm" variant="ghost" onClick={() => setSheet({ source: null })}>
            <PlusIcon />
            {tw("add")}
          </Button>
        </div>
      </Section>

      <Section title={t("logs.title")} description={t("logs.description")}>
        {logs === null && <Skeleton className="m-3 h-10" />}
        {logs?.length === 0 && <EmptyRow text={t("none")} action={t("connect")} href={SOURCES_URL} />}
        {logs?.map((source) => (
          <div key={source.id} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3 py-3">
            <span className="font-medium text-sm">{source.name}</span>
            <Badge variant={source.enabled ? "secondary" : "outline"}>
              {source.enabled ? t("enabled") : tw("disabled")}
            </Badge>
            <span className="text-muted-foreground text-xs">
              {t("updatedAt", { when: new Date(source.updated_at).toLocaleString() })}
            </span>
            <Button asChild size="sm" variant="outline" className="ml-auto">
              <Link href={SOURCES_URL}>
                {t("manage")}
                <ArrowRightIcon />
              </Link>
            </Button>
          </div>
        ))}
      </Section>

      <Section title={t("sync.title")} description={t("sync.description")}>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3 py-3">
          <span className="font-medium text-sm">ScopeSentry</span>
          <Badge variant={syncReady ? "secondary" : "outline"}>{syncReady ? t("enabled") : t("notConnected")}</Badge>
          {sync?.url && <span className="truncate font-mono text-muted-foreground text-xs">{sync.url}</span>}
          <Button asChild size="sm" variant="outline" className="ml-auto">
            <Link href={SYNC_URL}>
              {syncReady ? t("manage") : t("connect")}
              <ArrowRightIcon />
            </Link>
          </Button>
        </div>
      </Section>

      <WazuhConnectionSheet
        open={sheet !== null}
        onOpenChange={(open) => !open && setSheet(null)}
        source={sheet?.source ?? null}
        onSaved={() => void load()}
      />
    </div>
  );
}
