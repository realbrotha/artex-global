"use client";

import * as React from "react";

import { RefreshCwIcon, RotateCcwIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { ListEmpty, TableSkeletonRows } from "@/components/page";
import { StatusBadge } from "@/components/status-badge";
import { PAGE_SIZE, TablePagination } from "@/components/table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getDateLocale } from "@/i18n/datetime";
import { api } from "@/lib/api";
import type { NotificationChannel, NotificationDelivery } from "@/lib/types";

// DeliveryList 是投递记录表：可按渠道与状态筛选，失败项可手动重发。
export function DeliveryList({ channels }: { channels: NotificationChannel[] }) {
  const t = useTranslations("notifyPage");
  // 전송 상태·심각도 라벨은 전역 공유 `status` 네임스페이스에서 온다(StatusBadge 와 동일 출처).
  // lib/status.ts 의 중국어는 상류 대조용 죽은 폴백이라 직접 쓰지 않는다(턴 129 함정 참조).
  const ts = useTranslations("status");
  const [rows, setRows] = React.useState<NotificationDelivery[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(1);
  const [channelID, setChannelID] = React.useState<number | undefined>(undefined);
  const [state, setState] = React.useState<string | undefined>(undefined);
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .notifyDeliveries({ channelId: channelID, state, page, pageSize: PAGE_SIZE })
      .then((r) => {
        setRows(r.deliveries);
        setTotal(r.total);
      })
      .catch((e) => toast.error(t("delivery.loadFailed", { msg: (e as Error).message })))
      .finally(() => setLoading(false));
    // t 는 안정 참조라 deps 에 넣지 않아도 되지만, exhaustive-deps 를 만족시키려 포함.
  }, [channelID, state, page, t]);
  React.useEffect(() => {
    load();
  }, [load]);

  async function retry(id: number) {
    try {
      await api.notifyRetryDelivery(id);
      toast.success(t("delivery.requeued"));
      load();
    } catch (e) {
      toast.error(t("delivery.resendFailed", { msg: (e as Error).message }));
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={channelID ? String(channelID) : "all"}
          onValueChange={(v) => {
            setPage(1);
            setChannelID(v === "all" ? undefined : Number(v));
          }}
        >
          <SelectTrigger className="w-44">
            <SelectValue placeholder={t("delivery.allChannels")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("delivery.allChannels")}</SelectItem>
            {channels.map((c) => (
              <SelectItem key={c.id} value={String(c.id)}>
                {c.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={state ?? "all"}
          onValueChange={(v) => {
            setPage(1);
            setState(v === "all" ? undefined : v);
          }}
        >
          <SelectTrigger className="w-32">
            <SelectValue placeholder={t("delivery.allStates")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("delivery.allStates")}</SelectItem>
            {["pending", "sending", "sent", "failed", "skipped"].map((s) => (
              <SelectItem key={s} value={s}>
                {ts(`delivery.${s}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="ml-auto text-muted-foreground text-xs">{t("delivery.totalCount", { total })}</span>
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={load}
          disabled={loading}
          aria-label={t("delivery.refresh")}
          title={t("delivery.refresh")}
        >
          <RefreshCwIcon className={loading ? "animate-spin" : ""} />
        </Button>
      </div>

      {!loading && rows.length === 0 ? (
        <ListEmpty title={t("delivery.empty")} />
      ) : (
        <div className="rounded-xl border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-40">{t("delivery.colTime")}</TableHead>
                <TableHead>{t("delivery.colFinding")}</TableHead>
                <TableHead className="w-40">{t("delivery.colChannel")}</TableHead>
                <TableHead className="w-24">{t("delivery.colState")}</TableHead>
                <TableHead className="w-16">{t("delivery.colAttempts")}</TableHead>
                <TableHead>{t("delivery.colError")}</TableHead>
                <TableHead className="w-20" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableSkeletonRows columns={7} />
              ) : (
                rows.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="text-muted-foreground text-xs whitespace-nowrap">
                      {formatTime(d.created_at)}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <StatusBadge domain="severity" value={d.severity} />
                        <span className="truncate text-sm">{d.title || t("delivery.noTitle")}</span>
                        {d.event_kind === "finding_status_changed" && (
                          <Badge variant="outline" className="shrink-0">
                            {t("delivery.statusChanged")}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-sm">{d.channel_name}</TableCell>
                    <TableCell>
                      <StatusBadge domain="delivery" value={d.state} />
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">{d.attempts}</TableCell>
                    <TableCell className="text-muted-foreground max-w-md text-xs break-all">{d.last_error}</TableCell>
                    <TableCell>
                      {/* 只有失败/跳过的才给重发入口：已送达的重发会造成重复推送。 */}
                      {(d.state === "failed" || d.state === "skipped") && (
                        <Button size="xs" variant="outline" onClick={() => retry(d.id)}>
                          <RotateCcwIcon /> {t("delivery.resend")}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}

      <TablePagination page={page} total={total} onPageChange={setPage} />
    </div>
  );
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(getDateLocale(), { hour12: false });
}
