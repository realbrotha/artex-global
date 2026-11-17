"use client";

import * as React from "react";

import { UploadIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";
import { type AcceptedRisk, wazuhApi } from "@/lib/wazuh-api";

interface AcceptedRisksSheetProps {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  // Called after an import; the server re-syncs, so counts change shortly.
  readonly onChanged: () => void;
}

const today = () => new Date().toISOString().slice(0, 10);

// Shows the accepted-risk registry and replaces it from a TSV file in the
// Thaki-Siem registry/accepted-risks.tsv format.
export function AcceptedRisksSheet({ open, onOpenChange, onChanged }: AcceptedRisksSheetProps) {
  const t = useTranslations("protectedAssets.acceptedRisks");
  const [risks, setRisks] = React.useState<AcceptedRisk[] | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    if (!open) return;
    setRisks(null);
    setError("");
    wazuhApi
      .acceptedRisks()
      .then((r) => setRisks(r.risks))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : t("loadFailed")));
  }, [open, t]);

  const upload = async (file: File) => {
    setBusy(true);
    setError("");
    try {
      const r = await wazuhApi.replaceAcceptedRisks(await file.text());
      setRisks(r.risks);
      toast.success(t("imported", { count: r.risks.length }));
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("importFailed"));
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const day = today();

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full gap-0 overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>{t("title")}</SheetTitle>
          <SheetDescription>{t("description")}</SheetDescription>
        </SheetHeader>
        <div className="grid gap-3 px-4 pb-6">
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept=".tsv,.txt,text/tab-separated-values,text/plain"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void upload(file);
              }}
            />
            <Button size="sm" onClick={() => fileRef.current?.click()} disabled={busy}>
              {busy ? <Spinner /> : <UploadIcon />}
              {t("import")}
            </Button>
            <span className="text-muted-foreground text-xs">{t("importHelp")}</span>
          </div>
          {error && <p className="whitespace-pre-wrap text-destructive text-xs">{error}</p>}
          {risks === null && !error && <Skeleton className="h-32 w-full" />}
          {risks?.length === 0 && <p className="text-muted-foreground text-sm">{t("empty")}</p>}
          {risks && risks.length > 0 && (
            <ul className="grid grid-cols-1 gap-1.5">
              {risks.map((risk) => {
                const expired = Boolean(risk.until) && risk.until < day;
                return (
                  <li
                    key={`${risk.code}:${risk.host}`}
                    className={cn("grid grid-cols-1 gap-0.5 rounded border p-2 text-xs", expired && "opacity-60")}
                  >
                    <div className="flex flex-wrap items-baseline gap-x-2">
                      <span className="font-medium font-mono">{risk.code}</span>
                      <span className="text-muted-foreground">{risk.host === "*" ? t("allHosts") : risk.host}</span>
                      <span
                        className={cn("ml-auto text-[11px]", expired ? "text-destructive" : "text-muted-foreground")}
                      >
                        {expired
                          ? t("expired", { until: risk.until })
                          : t("until", { until: risk.until || t("noExpiry") })}
                      </span>
                    </div>
                    <p className="break-words">{risk.reason}</p>
                    <p className="text-[11px] text-muted-foreground">{t("approvedBy", { who: risk.approved_by })}</p>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
