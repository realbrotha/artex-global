"use client";

import * as React from "react";

import { RotateCcwIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { DrawerFooter } from "@/components/page";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { FindingRetest } from "@/lib/types";

interface FindingRetestDialogProps {
  findingId: string;
  findingName?: string;
  onClose: () => void;
  onStarted?: (retest: FindingRetest) => void;
}

// 오른쪽 드로어(sm). 仅在打开时挂载，关闭后清空说明；列表与详情共用提交锁及错误处理，启动后留在当前页。
export function FindingRetestDialog({ findingId, findingName, onClose, onStarted }: FindingRetestDialogProps) {
  const t = useTranslations("retest.dialog");
  const notesId = React.useId();
  const [notes, setNotes] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const submitLock = React.useRef(false);

  async function start() {
    if (submitLock.current) return;
    submitLock.current = true;
    setSubmitting(true);
    try {
      const result = await api.startFindingRetest(findingId, notes.trim());
      onStarted?.(result.retest);
      onClose();
      toast.success(result.created ? t("startedNew") : t("alreadyRunning"));
    } catch (e) {
      toast.error(t("startFailed", { message: (e as Error).message }));
    } finally {
      submitLock.current = false;
      setSubmitting(false);
    }
  }

  return (
    <Sheet open onOpenChange={(open) => !open && !submitLock.current && onClose()}>
      <SheetContent size="sm" className="gap-0">
        <SheetHeader className="border-b">
          <SheetTitle>{t("title", { id: findingId })}</SheetTitle>
          <SheetDescription className="break-words">
            {findingName ? <span className="mb-2 block">{findingName}</span> : null}
            {t("desc")}
          </SheetDescription>
        </SheetHeader>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
          <FieldGroup>
            <Field data-disabled={submitting}>
              <FieldLabel htmlFor={notesId}>{t("notesLabel")}</FieldLabel>
              <Textarea
                id={notesId}
                value={notes}
                maxLength={4000}
                rows={4}
                disabled={submitting}
                onChange={(e) => setNotes(e.target.value)}
                placeholder={t("notesPlaceholder")}
              />
              <FieldDescription>{t("notesDesc")}</FieldDescription>
            </Field>
          </FieldGroup>
        </div>
        <DrawerFooter
          onCancel={onClose}
          onConfirm={() => void start()}
          pending={submitting}
          confirmLabel={
            <>
              {submitting ? <Spinner data-icon="inline-start" /> : <RotateCcwIcon data-icon="inline-start" />}
              {submitting ? t("submitting") : t("submit")}
            </>
          }
        />
      </SheetContent>
    </Sheet>
  );
}
