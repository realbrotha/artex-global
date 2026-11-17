"use client";

import * as React from "react";

import Link from "next/link";

import { PlayIcon, PlusIcon, SaveIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { type ScheduleState, type SiemSchedule, scheduleApi } from "@/lib/wazuh-api";

const INTERVALS = [15, 30, 60, 120, 240, 360, 720, 1440];
// Monday first, as the week is read here; values are 0 = Sunday .. 6.
const WEEK = [1, 2, 3, 4, 5, 6, 0];

const stamp = (iso?: string | null) =>
  iso
    ? new Date(iso).toLocaleString(undefined, {
        month: "numeric",
        day: "numeric",
        weekday: "short",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "—";

function Row({
  label,
  hint,
  children,
}: {
  readonly label: string;
  readonly hint?: string;
  readonly children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-1 gap-2 border-b py-4 last:border-b-0 sm:grid-cols-[14rem_minmax(0,1fr)]">
      <div>
        <p className="font-medium text-sm">{label}</p>
        {hint && <p className="text-muted-foreground text-xs">{hint}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2 text-sm">{children}</div>
    </div>
  );
}

// Analysis schedule: when the SIEM log analysis runs by itself (collect
// alerts, extract cases) and how it judges them without a person.
export default function SchedulePage() {
  const t = useTranslations("siemSchedule");
  const [state, setState] = React.useState<ScheduleState | null>(null);
  const [draft, setDraft] = React.useState<SiemSchedule | null>(null);
  const [error, setError] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [running, setRunning] = React.useState(false);
  const [newTime, setNewTime] = React.useState("09:00");

  const load = React.useCallback(async () => {
    try {
      const next = await scheduleApi.get();
      setState(next);
      setDraft(next.schedule);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("loadFailed"));
    }
  }, [t]);

  React.useEffect(() => {
    void load();
  }, [load]);

  if (!draft) {
    return (
      <div className="flex flex-1 flex-col gap-4">
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : (
          <Skeleton className="h-96 w-full" />
        )}
      </div>
    );
  }

  const set = (patch: Partial<SiemSchedule>) => setDraft({ ...draft, ...patch });
  const dirty = JSON.stringify(draft) !== JSON.stringify(state?.schedule);

  const save = async () => {
    setSaving(true);
    try {
      const next = await scheduleApi.save(draft);
      setState(next);
      setDraft(next.schedule);
      setError("");
      toast.success(t("saved"));
    } catch (e) {
      setError(e instanceof Error ? e.message : t("saveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const runNow = async () => {
    setRunning(true);
    try {
      const r = await scheduleApi.runNow();
      toast.success(t("started", { count: r.started }));
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("runFailed"));
    } finally {
      setRunning(false);
    }
  };

  const addTime = () => {
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(newTime) || draft.times.includes(newTime)) return;
    set({ times: [...draft.times, newTime].sort() });
  };
  const toggleDay = (d: number) =>
    set({ weekdays: draft.weekdays.includes(d) ? draft.weekdays.filter((x) => x !== d) : [...draft.weekdays, d] });
  const segment = (on: boolean) =>
    cn(
      "rounded-md border px-2.5 py-1 text-xs",
      on ? "border-primary bg-primary text-primary-foreground" : "hover:bg-muted",
    );

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground text-sm">{t("subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void runNow()} disabled={running}>
            <PlayIcon />
            {t("runNow")}
          </Button>
          <Button size="sm" onClick={() => void save()} disabled={!dirty || saving}>
            <SaveIcon />
            {t("save")}
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="rounded-xl border bg-card px-4 py-3">
          <p className="text-[11px] text-muted-foreground">{t("status")}</p>
          <p className={cn("font-semibold", state?.schedule.enabled ? "text-emerald-600 dark:text-emerald-400" : "")}>
            {state?.schedule.enabled ? t("on") : t("off")}
          </p>
        </div>
        <div className="rounded-xl border bg-card px-4 py-3">
          <p className="text-[11px] text-muted-foreground">{t("lastRun")}</p>
          <p className="font-semibold">{stamp(state?.last_run)}</p>
          <Link href="/defensive/history" className="text-[11px] text-muted-foreground underline underline-offset-2">
            {t("history")}
          </Link>
        </div>
        <div className="rounded-xl border bg-card px-4 py-3">
          <p className="text-[11px] text-muted-foreground">{t("nextRun")}</p>
          <p className="font-semibold">{state?.schedule.enabled ? stamp(state?.next_run) : "—"}</p>
        </div>
      </div>

      <div className="rounded-xl border bg-card px-4">
        <Row label={t("enabled")} hint={t("enabledHint")}>
          <Switch checked={draft.enabled} onCheckedChange={(v) => set({ enabled: v })} />
        </Row>

        <Row label={t("mode")}>
          {(["interval", "daily"] as const).map((m) => (
            <button key={m} type="button" className={segment(draft.mode === m)} onClick={() => set({ mode: m })}>
              {t(`modes.${m}`)}
            </button>
          ))}
        </Row>

        {draft.mode === "interval" && (
          <Row label={t("interval")}>
            {INTERVALS.map((m) => (
              <button
                key={m}
                type="button"
                className={segment(draft.interval_minutes === m)}
                onClick={() => set({ interval_minutes: m })}
              >
                {m < 60 ? t("minutes", { count: m }) : t("hours", { count: m / 60 })}
              </button>
            ))}
          </Row>
        )}

        {draft.mode === "daily" && (
          <>
            <Row label={t("times")} hint={t("timesHint")}>
              {draft.times.map((time) => (
                <span key={time} className="flex items-center gap-1 rounded-md border px-2 py-1 font-mono text-xs">
                  {time}
                  <button
                    type="button"
                    aria-label={t("removeTime", { time })}
                    onClick={() => set({ times: draft.times.filter((x) => x !== time) })}
                    className="text-muted-foreground hover:text-foreground [&_svg]:size-3"
                  >
                    <XIcon />
                  </button>
                </span>
              ))}
              <Input
                type="time"
                value={newTime}
                onChange={(e) => setNewTime(e.target.value)}
                className="h-8 w-28 text-xs"
              />
              <Button size="xs" variant="outline" onClick={addTime}>
                <PlusIcon />
                {t("addTime")}
              </Button>
            </Row>
            <Row label={t("weekdays")} hint={t("weekdaysHint")}>
              {WEEK.map((d) => (
                <button
                  key={d}
                  type="button"
                  className={segment(draft.weekdays.includes(d))}
                  onClick={() => toggleDay(d)}
                >
                  {t(`day.${d}`)}
                </button>
              ))}
            </Row>
          </>
        )}

        <Row label={t("autoJudge")} hint={t("autoJudgeHint")}>
          <Switch checked={draft.auto_judge} onCheckedChange={(v) => set({ auto_judge: v })} />
        </Row>

        <Row label={t("debate")} hint={t("debateHint")}>
          <Switch checked={draft.debate} onCheckedChange={(v) => set({ debate: v })} disabled={!draft.auto_judge} />
        </Row>

        <Row label={t("limit")} hint={t("limitHint")}>
          <Input
            type="number"
            min={1}
            max={500}
            value={draft.judge_limit}
            onChange={(e) => set({ judge_limit: Number(e.target.value) || 1 })}
            className="h-8 w-24 text-xs"
            disabled={!draft.auto_judge}
          />
          <span className="text-muted-foreground text-xs">
            {t("limitCost", { tokens: Math.round((draft.judge_limit * 8.8) / 1) })}
          </span>
        </Row>
      </div>

      <div className="rounded-xl border bg-muted/30 p-4 text-xs">
        <p className="mb-2 font-medium text-sm">{t("flowTitle")}</p>
        <ol className="grid list-decimal grid-cols-1 gap-1 pl-4 text-muted-foreground">
          <li>{t("flow.1")}</li>
          <li>{t("flow.2")}</li>
          <li>{t("flow.3")}</li>
          <li>{t("flow.4")}</li>
          <li>{t("flow.5")}</li>
        </ol>
      </div>
    </div>
  );
}
