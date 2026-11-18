"use client";

// 화면 공통 틀 (CLAUDE.md 1.6 ~ 1.9). neocloud 의 ListPageTemplate · DetailPageTemplate ·
// 목록 상태 · 드로어 하단 · 확인 창을 shadcn/ui 로 옮긴 것. 페이지는 이 조각을 쓴다.

import * as React from "react";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { ChevronRightIcon, InboxIcon, RotateCwIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Alert, AlertAction, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { SheetFooter } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { TableCell, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { breadcrumbFor } from "@/navigation/sidebar/breadcrumb";

// 현재 주소의 메뉴 이름. 사이드 메뉴 설정에서 계산하므로 메뉴와 항상 같다.
export function usePageTitle() {
  const t = useTranslations("nav");
  const pathname = usePathname();
  const trail = breadcrumbFor(pathname);
  const last = trail[trail.length - 1];
  return last ? t(`item.${last.id}`) : "";
}

// 페이지 머리: 제목(20px) + 오른쪽 끝에 주 작업 버튼. 제목을 주지 않으면 메뉴 이름.
// children 은 제목 옆에 붙는 짧은 보조 정보(건수 등).
export function PageHeader({
  title,
  actions,
  children,
  className,
}: {
  readonly title?: React.ReactNode;
  readonly actions?: React.ReactNode;
  readonly children?: React.ReactNode;
  readonly className?: string;
}) {
  const fallback = usePageTitle();
  return (
    <div className={cn("flex min-h-9 flex-wrap items-center gap-x-3 gap-y-2", className)}>
      <h1 className="min-w-0 truncate font-semibold text-xl leading-7">{title ?? fallback}</h1>
      {children}
      {actions && <div className="ml-auto flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

// 상세 화면 머리 카드: 경로(목록 › 이름) · 이름 · 32px 작업 버튼 줄 · 요약 정보.
// 위험한 작업 버튼은 variant="outline" + className="text-danger".
export function DetailHeader({
  parent,
  title,
  badges,
  actions,
  children,
}: {
  readonly parent?: { readonly label: React.ReactNode; readonly href: string };
  readonly title: React.ReactNode;
  readonly badges?: React.ReactNode;
  readonly actions?: React.ReactNode;
  readonly children?: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-3 rounded-xl border bg-card px-5 py-4">
      {parent && (
        <nav aria-label="breadcrumb" className="flex items-center gap-1 text-muted-foreground text-sm">
          <Link prefetch={false} href={parent.href} className="hover:text-foreground">
            {parent.label}
          </Link>
          <ChevronRightIcon className="size-3.5" aria-hidden />
          <span className="min-w-0 truncate text-foreground">{title}</span>
        </nav>
      )}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h1 className="min-w-0 truncate font-semibold text-xl leading-7">{title}</h1>
        {badges}
        {actions && (
          <div data-detail-header-actions className="ml-auto flex flex-wrap items-center gap-2">
            {actions}
          </div>
        )}
      </div>
      {children}
    </section>
  );
}

// 목록 로딩: 표 뼈대 3줄. 빈 표나 화면 가운데 스피너를 쓰지 않는다.
export function TableSkeletonRows({ columns, rows = 3 }: { readonly columns: number; readonly rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, row) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: fixed placeholder rows
        <TableRow key={row}>
          {Array.from({ length: columns }, (_, col) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: fixed placeholder cells
            <TableCell key={col}>
              <Skeleton className="h-4 w-full max-w-40" />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  );
}

// 결과 없음 / 필터 결과 없음.
export function ListEmpty({
  title,
  description,
  action,
  icon,
  className,
}: {
  readonly title: React.ReactNode;
  readonly description?: React.ReactNode;
  readonly action?: React.ReactNode;
  readonly icon?: React.ReactNode;
  readonly className?: string;
}) {
  return (
    <Empty className={cn("rounded-xl border bg-card py-10", className)}>
      <EmptyHeader>
        <EmptyMedia variant="icon">{icon ?? <InboxIcon />}</EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        {description && <EmptyDescription>{description}</EmptyDescription>}
      </EmptyHeader>
      {action && <EmptyContent>{action}</EmptyContent>}
    </Empty>
  );
}

// 다시 시도할 수 있는 읽기 실패. 목록 위치에 그대로 둔다.
export function LoadError({
  message,
  onRetry,
  className,
}: {
  readonly message: React.ReactNode;
  readonly onRetry?: () => void;
  readonly className?: string;
}) {
  const t = useTranslations("common");
  return (
    <Alert variant="destructive" className={className}>
      <AlertDescription>{message}</AlertDescription>
      {onRetry && (
        <AlertAction>
          <Button variant="outline" size="xs" onClick={onRetry}>
            <RotateCwIcon />
            {t("retry")}
          </Button>
        </AlertAction>
      )}
    </Alert>
  );
}

// 드로어(Sheet) 하단: 가운데, 같은 폭의 취소(테두리) + 확인(채움).
export function DrawerFooter({
  onCancel,
  confirmLabel,
  onConfirm,
  confirmDisabled,
  pending,
  form,
}: {
  readonly onCancel: () => void;
  readonly confirmLabel: React.ReactNode;
  readonly onConfirm?: () => void;
  readonly confirmDisabled?: boolean;
  readonly pending?: boolean;
  /** 확인 버튼을 form 의 submit 으로 쓸 때 그 form 의 id */
  readonly form?: string;
}) {
  const t = useTranslations("common");
  return (
    <SheetFooter className="mt-auto grid grid-cols-2 gap-2 border-t">
      <Button type="button" variant="outline" onClick={onCancel}>
        {t("cancel")}
      </Button>
      <Button
        type={form ? "submit" : "button"}
        form={form}
        onClick={onConfirm}
        disabled={Boolean(confirmDisabled) || Boolean(pending)}
      >
        {confirmLabel}
      </Button>
    </SheetFooter>
  );
}

// window.confirm 대신 쓰는 확인 창. const confirm = useConfirm(); if (!(await confirm({...}))) return;
interface ConfirmOptions {
  readonly title: React.ReactNode;
  readonly description?: React.ReactNode;
  readonly confirmLabel?: React.ReactNode;
  /** 삭제처럼 되돌릴 수 없는 작업 */
  readonly destructive?: boolean;
}

const ConfirmContext = React.createContext<((options: ConfirmOptions) => Promise<boolean>) | null>(null);

export function ConfirmProvider({ children }: { readonly children: React.ReactNode }) {
  const t = useTranslations("common");
  const [state, setState] = React.useState<(ConfirmOptions & { resolve: (ok: boolean) => void }) | null>(null);
  const confirm = React.useCallback(
    (options: ConfirmOptions) => new Promise<boolean>((resolve) => setState({ ...options, resolve })),
    [],
  );
  const close = (ok: boolean) => {
    state?.resolve(ok);
    setState(null);
  };
  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <AlertDialog open={state !== null} onOpenChange={(open) => !open && close(false)}>
        <AlertDialogContent size="sm">
          <AlertDialogHeader>
            <AlertDialogTitle>{state?.title}</AlertDialogTitle>
            {state?.description && <AlertDialogDescription>{state.description}</AlertDialogDescription>}
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => close(false)}>{t("cancel")}</AlertDialogCancel>
            <AlertDialogAction variant={state?.destructive ? "destructive" : "default"} onClick={() => close(true)}>
              {state?.confirmLabel ?? t("confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </ConfirmContext.Provider>
  );
}

export function useConfirm() {
  const confirm = React.useContext(ConfirmContext);
  if (!confirm) throw new Error("useConfirm needs ConfirmProvider");
  return confirm;
}
