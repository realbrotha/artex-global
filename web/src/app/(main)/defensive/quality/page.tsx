"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowRightIcon, CheckIcon, PlayIcon, RefreshCwIcon, RotateCcwIcon, SaveIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { ListEmpty, LoadError, PageHeader, useConfirm } from "@/components/page";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import { type Check, type QualitySource, type QualityState, qualityApi } from "@/lib/wazuh-api";

import { verdictTone } from "../assets/_components/case-list";
import { FeedbackView } from "../feedback/_components/feedback-view";

const TABS = ["overview", "reviews", "checklist", "thresholds", "gaps", "golden", "feedback"] as const;
type Tab = (typeof TABS)[number];
const PATTERNS = ["*", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"];

const pct = (n: number, of: number) => (of > 0 ? `${Math.round((n / of) * 100)}%` : "—");
const when = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });

// Who does each step of a loop: the system by itself, or a person.
function Flow({ steps }: { readonly steps: readonly { label: string; human?: boolean }[] }) {
  const t = useTranslations("siemQuality");
  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-lg border bg-muted/30 p-2.5 text-[11px]">
      {steps.map((s, i) => (
        <React.Fragment key={s.label}>
          {i > 0 && <ArrowRightIcon className="size-3 text-muted-foreground" />}
          <span
            className={cn(
              "rounded border px-1.5 py-0.5",
              s.human ? "border-caution/50 bg-caution/10 text-caution" : "border-info/40 bg-info/10 text-info",
            )}
          >
            {s.label}
          </span>
        </React.Fragment>
      ))}
      <span className="ml-auto flex gap-3 text-muted-foreground">
        <span className="flex items-center gap-1">
          <span className="inline-block size-2 rounded-sm bg-info" />
          {t("auto")}
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block size-2 rounded-sm bg-caution" />
          {t("human")}
        </span>
      </span>
    </div>
  );
}

function Kpi({ label, value, note }: { readonly label: string; readonly value: string; readonly note?: string }) {
  return (
    <div className="rounded-xl border bg-card px-4 py-3">
      <p className="text-[11px] text-muted-foreground">{label}</p>
      <p className="font-semibold text-xl tabular-nums">{value}</p>
      {note && <p className="text-[11px] text-muted-foreground">{note}</p>}
    </div>
  );
}

const th = "border-b bg-muted/40 px-3 py-2 text-left font-normal text-[11px] text-muted-foreground";
const td = "border-b px-3 py-1.5 align-top";
const empty = "rounded-lg border border-dashed p-6 text-center text-muted-foreground text-xs";

function Overview({ data, s }: { readonly data: QualityState; readonly s: QualitySource }) {
  const t = useTranslations("siemQuality");
  const sum = s.weeks.reduce(
    (a, w) => ({
      judged: a.judged + w.judged,
      fallback: a.fallback + w.fallback,
      debated: a.debated + w.debated,
      reviews: a.reviews + w.reviews,
      agreed: a.agreed + w.agreed,
      changed: a.changed + w.changed,
      corrected: a.corrected + w.corrected,
    }),
    { judged: 0, fallback: 0, debated: 0, reviews: 0, agreed: 0, changed: 0, corrected: 0 },
  );
  const sched = data.schedule;
  const onOff = (b: boolean) => (b ? t("on") : t("off"));
  return (
    <div className="grid grid-cols-1 gap-4">
      <Flow
        steps={[
          { label: t("flow.judge") },
          { label: t("flow.review") },
          { label: t("flow.signal") },
          { label: t("flow.correct"), human: true },
          { label: t("flow.precedent") },
        ]}
      />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Kpi
          label={t("kpi.agree")}
          value={pct(sum.agreed, sum.reviews)}
          note={t("kpi.agreeNote", { n: sum.reviews, changed: sum.changed })}
        />
        <Kpi
          label={t("kpi.corrected")}
          value={String(sum.corrected)}
          note={t("kpi.correctedNote", { rate: pct(sum.corrected, sum.judged) })}
        />
        <Kpi
          label={t("kpi.fallback")}
          value={pct(sum.fallback, sum.judged)}
          note={t("kpi.fallbackNote", { n: sum.fallback, debated: sum.debated })}
        />
        <Kpi
          label={t("kpi.checked")}
          value={pct(s.checked, s.checked + s.unchecked)}
          note={t("kpi.checkedNote", { n: s.unchecked })}
        />
      </div>
      <div className="overflow-x-auto rounded-xl border bg-card text-xs">
        <table className="w-full min-w-[44rem] border-collapse">
          <thead>
            <tr>
              {["week", "judged", "debated", "fallback", "failed", "reviews", "agreeRate", "changed", "corrected"].map(
                (k) => (
                  <th key={k} className={cn(th, k !== "week" && "text-right")}>
                    {t(`weekCol.${k}`)}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {s.weeks.map((w) => (
              <tr key={w.week}>
                <td className={cn(td, "font-mono text-[11px]")}>{w.week}</td>
                {[w.judged, w.debated, w.fallback, w.failed, w.reviews].map((v, i) => (
                  // biome-ignore lint/suspicious/noArrayIndexKey: fixed column order
                  <td key={i} className={cn(td, "text-right tabular-nums", v === 0 && "text-muted-foreground/50")}>
                    {v}
                  </td>
                ))}
                <td className={cn(td, "text-right tabular-nums")}>{pct(w.agreed, w.reviews)}</td>
                <td className={cn(td, "text-right tabular-nums", w.changed > 0 && "text-caution")}>{w.changed}</td>
                <td className={cn(td, "text-right tabular-nums", w.corrected > 0 && "text-primary")}>{w.corrected}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="rounded-xl border bg-card p-3 text-xs">
        <p className="mb-2 font-medium text-sm">{t("loops")}</p>
        <dl className="grid grid-cols-[10rem_minmax(0,1fr)] gap-x-3 gap-y-1">
          <dt className="text-muted-foreground">{t("loop.schedule")}</dt>
          <dd>
            {sched.enabled
              ? sched.mode === "interval"
                ? t("loop.everyMin", { n: sched.interval_minutes })
                : sched.times.join(", ")
              : t("off")}
          </dd>
          <dt className="text-muted-foreground">{t("loop.judge")}</dt>
          <dd>
            {sched.auto_judge ? t("loop.judgeOn", { n: sched.judge_limit, debate: onOff(sched.debate) }) : t("off")}
          </dd>
          <dt className="text-muted-foreground">{t("loop.review")}</dt>
          <dd>
            {sched.review_limit > 0
              ? t("loop.reviewOn", { n: sched.review_limit, days: data.review_every_days })
              : t("off")}
          </dd>
          <dt className="text-muted-foreground">{t("loop.research")}</dt>
          <dd>{sched.research ? t("loop.researchOn") : t("off")}</dd>
          <dt className="text-muted-foreground">{t("loop.gap")}</dt>
          <dd>{sched.gap_review ? t("loop.gapOn", { last: s.gap_last || "—" }) : t("off")}</dd>
          <dt className="text-muted-foreground">{t("loop.golden")}</dt>
          <dd>
            {s.golden
              ? t("loop.goldenOn", { correct: s.golden.correct, total: s.golden.total })
              : t("loop.goldenNone", { n: s.golden_set })}
          </dd>
        </dl>
        <Link href="/system/schedule" className="mt-2 inline-block text-muted-foreground underline underline-offset-2">
          {t("openSchedule")}
        </Link>
      </div>
    </div>
  );
}

function Reviews({ data, s }: { readonly data: QualityState; readonly s: QualitySource }) {
  const t = useTranslations("siemQuality");
  const tc = useTranslations("protectedAssets.cases");
  return (
    <div className="grid grid-cols-1 gap-3">
      <Flow
        steps={[
          { label: t("flow.pick") },
          { label: t("flow.reread") },
          { label: t("flow.compare") },
          { label: t("flow.debate") },
          { label: t("flow.replace") },
        ]}
      />
      <p className="text-muted-foreground text-xs">
        {t("reviewsHint", { n: data.schedule.review_limit, days: data.review_every_days })}
      </p>
      {s.reviews.length === 0 ? (
        <p className={empty}>{t("noReviews")}</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card text-xs">
          <table className="w-full min-w-[52rem] border-collapse">
            <thead>
              <tr>
                {["when", "case", "verdict", "result", "why", "note"].map((k) => (
                  <th key={k} className={th}>
                    {t(`reviewCol.${k}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {s.reviews.map((r) => (
                <tr key={r.id}>
                  <td className={cn(td, "whitespace-nowrap text-muted-foreground tabular-nums")}>
                    {when(r.created_at)}
                  </td>
                  <td className={td}>
                    <Link href={`/defensive/history?run=${r.run_id}`} className="hover:underline">
                      {r.title || r.case_key}
                    </Link>
                    <span className="block font-mono text-[10px] text-muted-foreground">{r.case_key}</span>
                  </td>
                  <td className={cn(td, "whitespace-nowrap text-[10px]")}>
                    <span
                      className={cn(
                        "rounded border px-1.5 py-0.5",
                        verdictTone[r.prev],
                        r.changed && "line-through opacity-60",
                      )}
                    >
                      {tc(`verdict.${r.prev}`)}
                    </span>
                    {r.changed && (
                      <>
                        {" → "}
                        <span className={cn("rounded border px-1.5 py-0.5", verdictTone[r.new])}>
                          {tc(`verdict.${r.new}`)}
                        </span>
                      </>
                    )}
                  </td>
                  <td className={cn(td, "whitespace-nowrap")}>
                    {r.changed ? (
                      <span className="text-caution">{t("result.changed")}</span>
                    ) : r.agreed ? (
                      <span className="text-success">{t("result.agreed")}</span>
                    ) : (
                      <span className="text-warning">{t("result.kept")}</span>
                    )}
                  </td>
                  <td className={cn(td, "text-muted-foreground")}>{r.pick_reason}</td>
                  <td className={cn(td, "text-muted-foreground")}>{r.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const toText = (list: Check[] | undefined) => (list ?? []).map((c) => `${c.id} | ${c.question}`).join("\n");
const fromText = (text: string): Check[] =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [id, ...rest] = line.split("|");
      return { id: id.trim(), question: rest.join("|").trim() };
    });

function Checklist({
  data,
  s,
  onSaved,
}: {
  readonly data: QualityState;
  readonly s: QualitySource;
  readonly onSaved: () => void;
}) {
  const t = useTranslations("siemQuality");
  const [draft, setDraft] = React.useState<Record<string, string>>({});
  const [error, setError] = React.useState("");
  React.useEffect(() => {
    setDraft(Object.fromEntries(PATTERNS.map((p) => [p, toText(data.checklist[p])])));
  }, [data.checklist]);
  const dirty = PATTERNS.some((p) => (draft[p] ?? "") !== toText(data.checklist[p]));
  const save = async (reset: boolean) => {
    try {
      await qualityApi.saveChecklist(
        reset ? null : Object.fromEntries(PATTERNS.map((p) => [p, fromText(draft[p] ?? "")])),
      );
      setError("");
      toast.success(t("saved"));
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("saveFailed"));
    }
  };
  return (
    <div className="grid grid-cols-1 gap-3">
      <Flow
        steps={[
          { label: t("flow.editChecks"), human: true },
          { label: t("flow.facts") },
          { label: t("flow.answer") },
          { label: t("flow.reject") },
        ]}
      />
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-muted-foreground">
          {t("checklistHint")} {t("checklistStat", { ok: s.checked, none: s.unchecked })}
        </span>
        <span className="ml-auto flex gap-2">
          {data.checklist_edited && (
            <Button size="xs" variant="outline" onClick={() => void save(true)}>
              <RotateCcwIcon />
              {t("restore")}
            </Button>
          )}
          <Button size="xs" disabled={!dirty} onClick={() => void save(false)}>
            <SaveIcon />
            {t("save")}
          </Button>
        </span>
      </div>
      {error && <p className="break-words text-destructive text-xs">{error}</p>}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {PATTERNS.map((p) => (
          <div key={p} className={cn("grid grid-cols-1 gap-1 rounded-lg border p-3", p === "*" && "lg:col-span-2")}>
            <p className="font-medium text-xs">
              {p === "*" ? t("allPatterns") : p}{" "}
              <span className="font-normal text-muted-foreground">{p !== "*" && t(`pattern.${p}`)}</span>
            </p>
            <textarea
              value={draft[p] ?? ""}
              onChange={(e) => setDraft({ ...draft, [p]: e.target.value })}
              rows={Math.max(2, (draft[p] ?? "").split("\n").length)}
              spellCheck={false}
              className="w-full rounded-md border bg-background px-2 py-1 font-mono text-[11px] leading-relaxed"
            />
          </div>
        ))}
      </div>
    </div>
  );
}

function Thresholds({ data, s }: { readonly data: QualityState; readonly s: QualitySource }) {
  const t = useTranslations("siemQuality");
  return (
    <div className="grid grid-cols-1 gap-4">
      <Flow
        steps={[
          { label: t("flow.threshold") },
          { label: t("flow.under") },
          { label: t("flow.watch") },
          { label: t("flow.repeat") },
          { label: t("flow.lower"), human: true },
        ]}
      />
      <section className="grid grid-cols-1 gap-2">
        <h3 className="font-medium text-sm">{t("thresholds")}</h3>
        <p className="text-muted-foreground text-xs">{t("thresholdsHint")}</p>
        <div className="overflow-x-auto rounded-xl border bg-card text-xs">
          <table className="w-full min-w-[48rem] border-collapse">
            <thead>
              <tr>
                {["pattern", "name", "value", "below", "basis"].map((k) => (
                  <th key={k} className={th}>
                    {t(`thCol.${k}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.thresholds.map((x) => (
                <tr key={x.id}>
                  <td className={cn(td, "font-mono text-[11px]")}>{x.pattern}</td>
                  <td className={td}>{x.name}</td>
                  <td className={cn(td, "whitespace-nowrap font-medium")}>{x.value}</td>
                  <td className={cn(td, "text-muted-foreground")}>{x.below}</td>
                  <td className={cn(td, "text-muted-foreground")}>{x.basis}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="grid grid-cols-1 gap-2">
        <h3 className="font-medium text-sm">{t("watch", { count: s.watch.length })}</h3>
        <p className="text-muted-foreground text-xs">{t("watchHint")}</p>
        {s.watch.length === 0 ? (
          <p className={empty}>{t("noWatch")}</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border bg-card text-xs">
            <table className="w-full min-w-[52rem] border-collapse">
              <thead>
                <tr>
                  {["kind", "subject", "host", "count", "seen", "last", "note"].map((k) => (
                    <th key={k} className={th}>
                      {t(`watchCol.${k}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {s.watch.map((w) => (
                  <tr key={`${w.pattern}:${w.kind}:${w.subject}`}>
                    <td className={cn(td, "whitespace-nowrap")}>
                      <span className="font-mono text-[11px]">{w.pattern}</span>{" "}
                      <span
                        className={cn(
                          "rounded border px-1.5 py-0.5 text-[10px]",
                          w.kind === "slow" && "border-caution/50 text-caution",
                        )}
                      >
                        {t(`watchKind.${w.kind}`)}
                      </span>
                    </td>
                    <td className={cn(td, "break-all font-mono text-[11px]")}>{w.subject}</td>
                    <td className={td}>{w.host}</td>
                    <td className={cn(td, "whitespace-nowrap tabular-nums")}>
                      {w.count} / {w.threshold}
                      <span className="mt-0.5 block h-1 w-16 overflow-hidden rounded-full bg-muted">
                        <span
                          className="block h-full bg-warning"
                          style={{ width: `${Math.min(100, (w.count / w.threshold) * 100)}%` }}
                        />
                      </span>
                    </td>
                    <td className={cn(td, "text-right tabular-nums", w.seen_runs >= 3 && "font-medium text-caution")}>
                      {w.seen_runs}
                    </td>
                    <td className={cn(td, "whitespace-nowrap text-muted-foreground tabular-nums")}>{when(w.last)}</td>
                    <td className={cn(td, "text-muted-foreground")}>{w.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Gaps({ s, onChanged }: { readonly s: QualitySource; readonly onChanged: () => void }) {
  const t = useTranslations("siemQuality");
  const decide = async (id: number, status: "accepted" | "dismissed" | "open") => {
    await qualityApi.decide(id, status).catch(() => undefined);
    onChanged();
  };
  return (
    <div className="grid grid-cols-1 gap-4">
      <Flow
        steps={[
          { label: t("flow.unmatched") },
          { label: t("flow.trends") },
          { label: t("flow.gapReview") },
          { label: t("flow.propose") },
          { label: t("flow.decide"), human: true },
        ]}
      />
      <section className="grid grid-cols-1 gap-2">
        <h3 className="font-medium text-sm">
          {t("proposals", { count: s.proposals.filter((p) => p.status === "open").length })}
        </h3>
        <p className="text-muted-foreground text-xs">{t("proposalsHint", { last: s.gap_last || "—" })}</p>
        {s.proposals.length === 0 ? (
          <p className={empty}>{t("noProposals")}</p>
        ) : (
          <ul className="grid grid-cols-1 gap-1.5 text-xs">
            {s.proposals.map((p) => (
              <li
                key={p.id}
                className={cn("grid grid-cols-1 gap-1 rounded-lg border p-2.5", p.status !== "open" && "opacity-60")}
              >
                <span className="flex flex-wrap items-center gap-1.5">
                  <span className="rounded border px-1.5 py-0.5 text-[10px]">{t(`proposalKind.${p.kind}`)}</span>
                  <span className="font-medium">{p.title}</span>
                  {p.status !== "open" && (
                    <span className="text-[11px] text-muted-foreground">{t(`status.${p.status}`)}</span>
                  )}
                  <span className="ml-auto flex gap-1">
                    {p.status === "open" ? (
                      <>
                        <Button size="xs" variant="outline" onClick={() => void decide(p.id, "accepted")}>
                          <CheckIcon />
                          {t("accept")}
                        </Button>
                        <Button size="xs" variant="ghost" onClick={() => void decide(p.id, "dismissed")}>
                          <XIcon />
                          {t("dismiss")}
                        </Button>
                      </>
                    ) : (
                      <Button size="xs" variant="ghost" onClick={() => void decide(p.id, "open")}>
                        {t("reopen")}
                      </Button>
                    )}
                  </span>
                </span>
                <span className="break-words">{p.why}</span>
                {p.how && (
                  <span className="break-words text-muted-foreground">
                    {t("how")}: {p.how}
                  </span>
                )}
                {p.source && (
                  <span className="break-words text-[11px] text-muted-foreground">
                    {t("from")}: {p.source}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="grid grid-cols-1 gap-2">
        <h3 className="font-medium text-sm">{t("unmatched", { count: s.unmatched.length })}</h3>
        <p className="text-muted-foreground text-xs">{t("unmatchedHint")}</p>
        {s.unmatched.length === 0 ? (
          <p className={empty}>{t("noUnmatched")}</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border bg-card text-xs">
            <table className="w-full min-w-[40rem] border-collapse">
              <thead>
                <tr>
                  {["rule", "level", "desc", "count", "hosts"].map((k) => (
                    <th key={k} className={cn(th, (k === "count" || k === "hosts" || k === "level") && "text-right")}>
                      {t(`ruleCol.${k}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {s.unmatched.map((r) => (
                  <tr key={r.id}>
                    <td className={cn(td, "font-mono text-[11px]")}>{r.id}</td>
                    <td className={cn(td, "text-right tabular-nums", r.level >= 10 && "font-medium text-danger")}>
                      {r.level}
                    </td>
                    <td className={td}>{r.desc}</td>
                    <td className={cn(td, "text-right tabular-nums")}>{r.count.toLocaleString()}</td>
                    <td className={cn(td, "text-right tabular-nums")}>{r.hosts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Golden({ s, onChanged }: { readonly s: QualitySource; readonly onChanged: () => void }) {
  const t = useTranslations("siemQuality");
  const tc = useTranslations("protectedAssets.cases");
  const g = s.golden;
  const confirm = useConfirm();
  const run = async () => {
    if (!(await confirm({ title: t("goldenConfirm", { n: s.golden_set }) }))) return;
    await qualityApi.runGolden(s.id).catch(() => undefined);
    setTimeout(onChanged, 1500);
  };
  return (
    <div className="grid grid-cols-1 gap-3">
      <Flow
        steps={[
          { label: t("flow.correct"), human: true },
          { label: t("flow.answerSet") },
          { label: t("flow.replay"), human: true },
          { label: t("flow.accuracy") },
        ]}
      />
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <span className="text-muted-foreground">{t("goldenHint", { n: s.golden_set })}</span>
        <Button
          size="xs"
          variant="outline"
          className="ml-auto"
          disabled={s.golden_set === 0 || g?.running}
          onClick={() => void run()}
        >
          <PlayIcon />
          {g?.running ? t("goldenRunning") : t("goldenRun")}
        </Button>
      </div>
      {!g ? (
        <p className={empty}>{s.golden_set === 0 ? t("goldenEmpty") : t("goldenNever")}</p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
            <Kpi
              label={t("goldenAccuracy")}
              value={pct(g.correct, g.items.length)}
              note={`${g.correct} / ${g.items.length}`}
            />
            <Kpi label={t("goldenAt")} value={when(g.at)} note={g.model} />
          </div>
          <div className="overflow-x-auto rounded-xl border bg-card text-xs">
            <table className="w-full min-w-[40rem] border-collapse">
              <thead>
                <tr>
                  {["case", "expected", "got", "method"].map((k) => (
                    <th key={k} className={th}>
                      {t(`goldenCol.${k}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {g.items.map((i) => (
                  <tr key={i.case_key} className={cn(i.got !== i.expected && "bg-caution/5")}>
                    <td className={td}>
                      {i.title || i.case_key}
                      <span className="block font-mono text-[10px] text-muted-foreground">{i.case_key}</span>
                    </td>
                    <td className={td}>{tc(`verdict.${i.expected}`)}</td>
                    <td className={cn(td, i.got !== i.expected && "font-medium text-caution")}>
                      {i.got ? tc(`verdict.${i.got}`) : i.error}
                    </td>
                    <td className={cn(td, "text-muted-foreground")}>{i.method && tc(`method.${i.method}`)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

// Detection quality: the loops that keep the automatic judging honest, each
// on its own tab with what it did and where a person decides.
export default function QualityPage() {
  const t = useTranslations("siemQuality");
  const [data, setData] = React.useState<QualityState | null>(null);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [tab, setTab] = React.useState<Tab>("overview");
  const [sourceId, setSourceId] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      setData(await qualityApi.get());
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("loadFailed"));
    } finally {
      setLoading(false);
    }
  }, [t]);
  React.useEffect(() => {
    const wanted = new URLSearchParams(window.location.search).get("tab");
    if (TABS.includes(wanted as Tab)) setTab(wanted as Tab);
    void load();
  }, [load]);

  const source = data?.sources.find((s) => s.id === sourceId) ?? data?.sources[0];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        actions={
          <>
            {(data?.sources.length ?? 0) > 1 && (
              <Select value={source?.id} onValueChange={setSourceId}>
                <SelectTrigger className="w-48">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {data?.sources.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={() => void load()}
              disabled={loading}
              aria-label={t("refresh")}
              title={t("refresh")}
            >
              <RefreshCwIcon className={cn(loading && "animate-spin")} />
            </Button>
          </>
        }
      />
      <div className="-mb-2 flex flex-wrap items-center gap-2">
        <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)}>
          <TabsList>
            {TABS.map((k) => (
              <TabsTrigger key={k} value={k}>
                {t(`tab.${k}`)}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>
      {error && <LoadError message={error} onRetry={() => void load()} />}
      {data === null && !error && <Skeleton className="h-96 w-full" />}
      {data && !source && <ListEmpty title={t("empty")} />}
      {data && source && tab === "overview" && <Overview data={data} s={source} />}
      {data && source && tab === "reviews" && <Reviews data={data} s={source} />}
      {data && source && tab === "checklist" && <Checklist data={data} s={source} onSaved={() => void load()} />}
      {data && source && tab === "thresholds" && <Thresholds data={data} s={source} />}
      {data && source && tab === "gaps" && <Gaps s={source} onChanged={() => void load()} />}
      {data && source && tab === "golden" && <Golden s={source} onChanged={() => void load()} />}
      {tab === "feedback" && <FeedbackView />}
    </div>
  );
}
