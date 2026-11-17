"use client";

import * as React from "react";

import Link from "next/link";

import { CableIcon, ServerIcon, ShieldAlertIcon, SirenIcon, SparklesIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { assetStatusGroup, type CaseSeverity, isHostNode, type SiemCase, wazuhApi } from "@/lib/wazuh-api";

import { isCleared, needsVerdict } from "../../defensive/assets/_components/case-list";

const ASSETS_URL = "/defensive/assets";
const SEVERITIES: CaseSeverity[] = ["Critical", "High", "Medium", "Low"];

interface Summary {
  connected: boolean;
  hosts: number;
  down: number;
  missing: number;
  fail: number;
  accepted: number;
  failingHosts: number;
  live: SiemCase[];
  unjudged: number;
}

function Tile({
  href,
  icon,
  label,
  value,
  tone,
  children,
}: {
  readonly href: string;
  readonly icon: React.ReactNode;
  readonly label: string;
  readonly value: number;
  readonly tone?: string;
  readonly children: React.ReactNode;
}) {
  return (
    <Link
      href={href}
      className="grid grid-cols-1 gap-1 rounded-xl border bg-card p-4 shadow-xs transition-colors hover:bg-muted/50"
    >
      <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground [&_svg]:size-3.5">
        {icon}
        {label}
      </span>
      <span className={cn("font-semibold text-2xl tabular-nums", tone)}>{value.toLocaleString()}</span>
      <span className="text-[11px] text-muted-foreground">{children}</span>
    </Link>
  );
}

// What the connected Wazuh says right now. Every tile opens the Assets tab
// that holds the detail behind its number.
export function SiemSummary() {
  const t = useTranslations("dashboard.siem");
  const tc = useTranslations("protectedAssets.cases");
  const [summary, setSummary] = React.useState<Summary | null>(null);

  React.useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [a, k] = await Promise.all([wazuhApi.assets(), wazuhApi.cases()]);
        if (!alive) return;
        const hosts = a.sources.flatMap((s) => s.nodes.filter(isHostNode));
        const cases = k.sources.flatMap((s) => s.cases);
        setSummary({
          connected: a.sources.length > 0,
          hosts: hosts.length,
          down: hosts.filter((h) => assetStatusGroup(h) === "down").length,
          missing: hosts.filter((h) => assetStatusGroup(h) === "missing").length,
          fail: hosts.reduce((n, h) => n + (h.checks?.fail ?? 0), 0),
          accepted: hosts.reduce((n, h) => n + (h.checks?.accepted ?? 0), 0),
          failingHosts: hosts.filter((h) => (h.checks?.fail ?? 0) > 0).length,
          live: cases.filter((c) => !isCleared(c)),
          unjudged: cases.filter(needsVerdict).length,
        });
      } catch {
        /* transient errors — next poll retries */
      }
    };
    void load();
    const timer = setInterval(() => void load(), 60_000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  if (!summary) return null;
  if (!summary.connected) {
    return (
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-dashed p-4">
        <p className="min-w-0 flex-1 text-muted-foreground text-sm">{t("notConnected")}</p>
        <Button asChild size="sm">
          <Link href="/system/connections">
            <CableIcon />
            {t("connect")}
          </Link>
        </Button>
      </div>
    );
  }

  const bySeverity = SEVERITIES.map((s) => [s, summary.live.filter((c) => c.severity === s).length] as const).filter(
    ([, n]) => n > 0,
  );

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Tile href={ASSETS_URL} icon={<ServerIcon />} label={t("hosts")} value={summary.hosts}>
        {summary.down + summary.missing > 0
          ? t("hostsDetail", { down: summary.down, missing: summary.missing })
          : t("hostsOk")}
      </Tile>
      <Tile
        href={`${ASSETS_URL}?tab=list`}
        icon={<ShieldAlertIcon />}
        label={t("fails")}
        value={summary.fail}
        tone={summary.fail > 0 ? "text-red-600 dark:text-red-400" : undefined}
      >
        {t("failsDetail", { hosts: summary.failingHosts, accepted: summary.accepted })}
      </Tile>
      <Tile
        href={`${ASSETS_URL}?tab=cases`}
        icon={<SirenIcon />}
        label={t("cases")}
        value={summary.live.length}
        tone={summary.live.length > 0 ? "text-orange-600 dark:text-orange-400" : undefined}
      >
        {bySeverity.length > 0 ? bySeverity.map(([s, n]) => `${tc(`severity.${s}`)} ${n}`).join(" · ") : t("casesNone")}
      </Tile>
      <Tile href={`${ASSETS_URL}?tab=cases`} icon={<SparklesIcon />} label={t("unjudged")} value={summary.unjudged}>
        {summary.unjudged > 0 ? t("unjudgedDetail") : t("unjudgedNone")}
      </Tile>
    </div>
  );
}
