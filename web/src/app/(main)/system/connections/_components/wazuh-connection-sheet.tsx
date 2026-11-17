"use client";

import * as React from "react";

import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { type WazuhSource, wazuhApi } from "@/lib/wazuh-api";

type TlsMode = "verify" | "pin" | "skip";

interface FormState {
  id: string | null;
  revision: number;
  name: string;
  managerUrl: string;
  indexerUrl: string;
  tlsMode: TlsMode;
  fingerprint: string;
  enabled: boolean;
  managerUser: string;
  managerPassword: string;
  indexerUser: string;
  indexerPassword: string;
}

const emptyForm: FormState = {
  id: null,
  revision: 0,
  name: "",
  managerUrl: "",
  indexerUrl: "",
  tlsMode: "verify",
  fingerprint: "",
  enabled: true,
  managerUser: "",
  managerPassword: "",
  indexerUser: "",
  indexerPassword: "",
};

function formOf(source: WazuhSource): FormState {
  const c = source.config;
  return {
    ...emptyForm,
    id: source.id,
    revision: source.revision,
    name: source.name,
    managerUrl: c.manager_url,
    indexerUrl: c.indexer_url,
    tlsMode: c.tls_fingerprint ? "pin" : c.tls_skip_verify ? "skip" : "verify",
    fingerprint: c.tls_fingerprint,
    enabled: source.enabled,
  };
}

interface WazuhConnectionSheetProps {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  // Connection to edit; null creates a new one.
  readonly source: WazuhSource | null;
  readonly onSaved: () => void;
}

// Create/edit form for one Wazuh connection. Stored credentials are never
// sent back, so empty credential fields keep what is stored.
export function WazuhConnectionSheet({ open, onOpenChange, source, onSaved }: WazuhConnectionSheetProps) {
  const t = useTranslations("protectedAssets.connection");
  const [form, setForm] = React.useState<FormState>(emptyForm);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (open) setForm(source ? formOf(source) : emptyForm);
  }, [open, source]);

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  const save = async () => {
    setBusy(true);
    try {
      await wazuhApi.save(form.id, {
        name: form.name,
        enabled: form.enabled,
        expected_revision: form.revision,
        config: {
          manager_url: form.managerUrl,
          indexer_url: form.indexerUrl,
          tls_fingerprint: form.tlsMode === "pin" ? form.fingerprint : "",
          tls_skip_verify: form.tlsMode === "skip",
        },
        manager_user: form.managerUser || undefined,
        manager_password: form.managerPassword || undefined,
        indexer_user: form.indexerUser || undefined,
        indexer_password: form.indexerPassword || undefined,
      });
      toast.success(t("saved"));
      onOpenChange(false);
      onSaved();
    } catch (error) {
      toast.error(error instanceof Error && error.message ? error.message : t("failed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full gap-0 overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>{form.id ? t("editTitle") : t("createTitle")}</SheetTitle>
          <SheetDescription>{t("formDescription")}</SheetDescription>
        </SheetHeader>

        <form
          className="grid gap-4 px-4 pb-6"
          onSubmit={(event) => {
            event.preventDefault();
            void save();
          }}
        >
          <div className="grid gap-1.5">
            <Label htmlFor="wz-name">{t("name")}</Label>
            <Input id="wz-name" value={form.name} onChange={(e) => set("name", e.target.value)} required />
          </div>

          <fieldset className="grid gap-3 rounded-lg border p-3">
            <legend className="px-1 font-medium text-sm">{t("managerSection")}</legend>
            <div className="grid gap-1.5">
              <Label htmlFor="wz-manager-url">{t("managerUrl")}</Label>
              <Input
                id="wz-manager-url"
                value={form.managerUrl}
                onChange={(e) => set("managerUrl", e.target.value)}
                placeholder="https://localhost:55000"
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="wz-manager-user">{t("user")}</Label>
                <Input
                  id="wz-manager-user"
                  value={form.managerUser}
                  onChange={(e) => set("managerUser", e.target.value)}
                  autoComplete="off"
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="wz-manager-password">{t("password")}</Label>
                <Input
                  id="wz-manager-password"
                  type="password"
                  value={form.managerPassword}
                  onChange={(e) => set("managerPassword", e.target.value)}
                  autoComplete="new-password"
                />
              </div>
            </div>
          </fieldset>

          <fieldset className="grid gap-3 rounded-lg border p-3">
            <legend className="px-1 font-medium text-sm">{t("indexerSection")}</legend>
            <p className="text-muted-foreground text-xs">{t("indexerHelp")}</p>
            <div className="grid gap-1.5">
              <Label htmlFor="wz-indexer-url">{t("indexerUrl")}</Label>
              <Input
                id="wz-indexer-url"
                value={form.indexerUrl}
                onChange={(e) => set("indexerUrl", e.target.value)}
                placeholder="https://localhost:9200"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="wz-indexer-user">{t("user")}</Label>
                <Input
                  id="wz-indexer-user"
                  value={form.indexerUser}
                  onChange={(e) => set("indexerUser", e.target.value)}
                  autoComplete="off"
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="wz-indexer-password">{t("password")}</Label>
                <Input
                  id="wz-indexer-password"
                  type="password"
                  value={form.indexerPassword}
                  onChange={(e) => set("indexerPassword", e.target.value)}
                  autoComplete="new-password"
                />
              </div>
            </div>
          </fieldset>

          {form.id && <p className="text-muted-foreground text-xs">{t("keepCredentials")}</p>}

          <div className="grid gap-1.5">
            <Label htmlFor="wz-tls">{t("tls")}</Label>
            <NativeSelect id="wz-tls" value={form.tlsMode} onChange={(e) => set("tlsMode", e.target.value as TlsMode)}>
              <NativeSelectOption value="verify">{t("tlsVerify")}</NativeSelectOption>
              <NativeSelectOption value="pin">{t("tlsPin")}</NativeSelectOption>
              <NativeSelectOption value="skip">{t("tlsSkip")}</NativeSelectOption>
            </NativeSelect>
            {form.tlsMode === "pin" && (
              <Input
                value={form.fingerprint}
                onChange={(e) => set("fingerprint", e.target.value)}
                placeholder={t("fingerprintPlaceholder")}
                className="font-mono text-xs"
                required
              />
            )}
            {form.tlsMode === "skip" && (
              <p className="text-amber-600 text-xs dark:text-amber-400">{t("tlsSkipHelp")}</p>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Switch id="wz-enabled" checked={form.enabled} onCheckedChange={(v) => set("enabled", v)} />
            <Label htmlFor="wz-enabled">{t("enabled")}</Label>
          </div>

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t("cancel")}
            </Button>
            <Button type="submit" disabled={busy}>
              {busy && <Spinner />}
              {t("save")}
            </Button>
          </div>
        </form>
      </SheetContent>
    </Sheet>
  );
}
