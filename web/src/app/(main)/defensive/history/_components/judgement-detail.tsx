"use client";

import * as React from "react";

import { ChevronRightIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { historyApi, type Judgement } from "@/lib/wazuh-api";

import { severityTone, stamp, verdictTone } from "../../assets/_components/case-list";

// The first request is the case and its timeline as JSON: indent it. A
// retry has correction text appended and is shown as sent.
function readable(text: string): string {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

function Block({
  title,
  note,
  text,
  open = false,
  tone,
}: {
  readonly title: string;
  readonly note?: string;
  readonly text: string;
  readonly open?: boolean;
  readonly tone?: string;
}) {
  const [shown, setShown] = React.useState(open);
  return (
    <div className="rounded-md border">
      <button
        type="button"
        onClick={() => setShown(!shown)}
        aria-expanded={shown}
        className="flex w-full items-center gap-1.5 px-2 py-1.5 text-left hover:bg-muted/60"
      >
        <ChevronRightIcon className={cn("size-3 text-muted-foreground transition-transform", shown && "rotate-90")} />
        <span className={cn("font-medium", tone)}>{title}</span>
        {note && <span className="ml-auto text-[11px] text-muted-foreground tabular-nums">{note}</span>}
      </button>
      {shown && (
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all border-t bg-muted/30 p-2 font-mono text-[11px] leading-relaxed">
          {text}
        </pre>
      )}
    </div>
  );
}

// One judgment in full: the case as it was, the outcome, and every request
// sent to the model with the answer it gave.
interface JudgementDetailProps {
  readonly id: number;
  // The owner already shows the case: leave its section out.
  readonly hideCase?: boolean;
}

export function JudgementDetail({ id, hideCase = false }: JudgementDetailProps) {
  const t = useTranslations("protectedAssets.history");
  const tc = useTranslations("protectedAssets.cases");
  const [data, setData] = React.useState<Judgement | "error" | null>(null);

  React.useEffect(() => {
    let alive = true;
    setData(null);
    historyApi
      .judgement(id)
      .then((j) => alive && setData(j))
      .catch(() => alive && setData("error"));
    return () => {
      alive = false;
    };
  }, [id]);

  if (data === null) return <Skeleton className="h-40 w-full" />;
  if (data === "error") return <p className="text-destructive text-xs">{t("detail.loadFailed")}</p>;

  const c = data.case;
  const v = data.verdict;
  const attempts = data.attempts ?? [];
  const sec = (ms: number) => t("sec", { sec: (ms / 1000).toFixed(1) });
  const size = (text: string) => t("detail.chars", { count: text.length.toLocaleString() });

  return (
    <div className="grid grid-cols-1 gap-3 text-xs">
      <section className={cn("grid grid-cols-1 gap-1", hideCase && "hidden")}>
        <p className="text-[11px] text-muted-foreground">{t("detail.case")}</p>
        <p className="flex flex-wrap items-center gap-1.5">
          <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", severityTone[c.severity])}>
            {tc(`severity.${c.severity}`)}
          </span>
          <span className="font-medium">{c.title ?? c.criterion}</span>
          <span className="font-mono text-[10px] text-muted-foreground">{c.criterion}</span>
        </p>
        <p className="break-words text-muted-foreground">{c.summary}</p>
        <dl className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-x-2 gap-y-0.5">
          {(
            [
              [tc("field.actor"), c.actor],
              [tc("field.hosts"), c.hosts.join(", ")],
              [t("detail.period"), `${stamp(c.first)} ~ ${stamp(c.last)} · ${t("detail.events", { count: c.n })}`],
              [t("detail.basis"), c.sev_basis],
              [tc("field.attack"), c.attack.join(", ")],
            ] as const
          )
            .filter(([, value]) => value)
            .map(([label, value]) => (
              <React.Fragment key={label}>
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="break-words">{value}</dd>
              </React.Fragment>
            ))}
        </dl>
      </section>

      <section className="grid grid-cols-1 gap-1">
        <p className="text-[11px] text-muted-foreground">{t("detail.outcome")}</p>
        {v ? (
          <div className="grid grid-cols-1 gap-1.5 rounded-md bg-muted/40 p-2">
            <p className="flex flex-wrap items-center gap-1.5">
              <span className={cn("rounded border px-1.5 py-0.5 text-[10px]", verdictTone[v.verdict])}>
                {tc(`verdict.${v.verdict}`)}
              </span>
              <span className="font-medium">{v.title}</span>
            </p>
            <p className="break-words">{v.explain}</p>
            {v.adjust && <p>{t("detail.adjust", { severity: v.severity, reason: v.adjust })}</p>}
            {v.evidence.length > 0 && (
              <div>
                <p className="text-[10px] text-muted-foreground">{t("detail.evidence")}</p>
                <ul className="grid grid-cols-1 gap-0.5">
                  {v.evidence.map((line, index) => (
                    <li key={`${index}:${line}`} className="break-all font-mono text-[11px]">
                      {line}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {(v.response?.length ?? 0) > 0 && (
              <div>
                <p className="text-[10px] text-muted-foreground">{t("detail.response")}</p>
                <ul className="list-disc pl-4">
                  {v.response?.map((action) => (
                    <li key={action} className="break-words">
                      {action}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ) : (
          <p className="break-words rounded-md bg-destructive/10 p-2 text-destructive">
            {t("detail.error")}: {data.error}
          </p>
        )}
        <p className="text-[11px] text-muted-foreground">
          {[
            data.model,
            new Date(data.judged_at).toLocaleString(),
            sec(data.ms),
            v?.method && tc(`method.${v.method}`),
            v?.confidence && `confidence ${v.confidence}`,
          ]
            .filter(Boolean)
            .join(" · ")}
        </p>
      </section>

      <section className="grid grid-cols-1 gap-1.5">
        <p className="text-[11px] text-muted-foreground">{t("detail.sent")}</p>
        {data.system_prompt && (
          <Block title={t("detail.system")} note={size(data.system_prompt)} text={data.system_prompt} />
        )}
        {data.reason && (
          <p className="rounded-md bg-primary/10 p-2 text-primary">
            {t("role.reason")}: {data.reason}
          </p>
        )}
        {attempts.map((attempt, index) => {
          const role = attempt.role ?? "analyst";
          const prevRole = index > 0 ? (attempts[index - 1].role ?? "analyst") : null;
          const retry = index > 0 && prevRole === role;
          return (
            // biome-ignore lint/suspicious/noArrayIndexKey: attempts are stored in order and never reordered
            <React.Fragment key={index}>
              {prevRole !== role && <p className="mt-1 font-medium text-[11px]">{t(`role.${role}`)}</p>}
              {retry && <p className="text-[11px] text-warning">{t("detail.retry")}</p>}
              {attempt.system && prevRole !== role && (
                <Block title={t("role.roleSystem")} note={size(attempt.system)} text={attempt.system} />
              )}
              <Block
                title={t("detail.request", { n: index + 1 })}
                note={size(attempt.prompt)}
                text={readable(attempt.prompt)}
                open={index === 0}
              />
              <Block
                title={t("detail.answer", { n: index + 1 })}
                note={sec(attempt.ms)}
                text={
                  attempt.error ? attempt.error : attempt.response ? readable(attempt.response) : t("detail.noAnswer")
                }
                open
                tone={attempt.error ? "text-destructive" : undefined}
              />
            </React.Fragment>
          );
        })}
      </section>
    </div>
  );
}
