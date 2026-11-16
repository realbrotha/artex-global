"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowRightIcon, CheckIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

const DISMISS_KEY = "artex.onboarding.dismissed";

interface OnboardingChecklistProps {
  /** 모든 원천 데이터가 한 번 이상 로드됐는지. false 인 동안은 렌더하지 않는다(깜빡임 방지). */
  readonly ready: boolean;
  readonly llmConfigured: boolean;
  readonly hasTasks: boolean;
  readonly hasFindings: boolean;
}

// 첫 사용 흐름(LLM 연결 → 작업 생성 → 결과 확인)을 안내한다.
// 전 단계 완료 또는 사용자가 닫으면 사라진다.
export function OnboardingChecklist({ ready, llmConfigured, hasTasks, hasFindings }: OnboardingChecklistProps) {
  const t = useTranslations("dashboard.onboarding");
  const [dismissed, setDismissed] = React.useState(true);

  React.useEffect(() => {
    try {
      setDismissed(window.localStorage.getItem(DISMISS_KEY) === "1");
    } catch {
      setDismissed(false);
    }
  }, []);

  const steps = [
    { id: "llm", done: llmConfigured, href: "/system/llm" },
    { id: "task", done: hasTasks, href: "/function/tasks" },
    { id: "findings", done: hasFindings, href: "/function/findings" },
  ] as const;
  const doneCount = steps.filter((s) => s.done).length;

  if (!ready || dismissed || doneCount === steps.length) return null;

  const dismiss = () => {
    setDismissed(true);
    try {
      window.localStorage.setItem(DISMISS_KEY, "1");
    } catch {
      /* 저장 불가 환경에서는 이번 화면에서만 닫는다 */
    }
  };

  const nextIndex = steps.findIndex((s) => !s.done);

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="font-semibold text-sm">{t("title")}</h2>
            <p className="text-muted-foreground text-xs">{t("subtitle")}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <span className="text-muted-foreground text-xs tabular-nums">
              {t("progress", { done: doneCount, total: steps.length })}
            </span>
            <button
              type="button"
              onClick={dismiss}
              aria-label={t("dismiss")}
              title={t("dismiss")}
              className="rounded-md p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              <XIcon className="size-3.5" />
            </button>
          </div>
        </div>

        <Progress value={(doneCount / steps.length) * 100} className="h-1" />

        <ol className="grid gap-2 md:grid-cols-3">
          {steps.map((step, index) => {
            const isNext = index === nextIndex;
            return (
              <li
                key={step.id}
                className={cn(
                  "flex flex-col gap-2 rounded-lg border p-3",
                  step.done && "bg-muted/30",
                  isNext && "border-primary/50",
                )}
              >
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "flex size-5 shrink-0 items-center justify-center rounded-full border font-medium text-[10px]",
                      step.done && "border-emerald-500 bg-emerald-500 text-white",
                    )}
                  >
                    {step.done ? <CheckIcon className="size-3" /> : index + 1}
                  </span>
                  <span className={cn("font-medium text-sm", step.done && "text-muted-foreground line-through")}>
                    {t(`${step.id}.title`)}
                  </span>
                </div>
                <p className="flex-1 text-muted-foreground text-xs">{t(`${step.id}.desc`)}</p>
                {!step.done && (
                  <Link
                    prefetch={false}
                    href={step.href}
                    className={cn(
                      buttonVariants({ variant: isNext ? "default" : "outline", size: "sm" }),
                      "self-start",
                    )}
                  >
                    {t(`${step.id}.action`)} <ArrowRightIcon />
                  </Link>
                )}
              </li>
            );
          })}
        </ol>
      </CardContent>
    </Card>
  );
}
