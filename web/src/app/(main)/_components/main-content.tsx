"use client";

import { type ReactNode, useEffect, useState } from "react";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { useTranslations } from "next-intl";

import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { useCurrentUser } from "@/hooks/use-current-user";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { breadcrumbFor } from "@/navigation/sidebar/breadcrumb";

import { AccountSwitcher } from "./sidebar/account-switcher";
import { LayoutControls } from "./sidebar/layout-controls";
import { ThemeSwitcher } from "./sidebar/theme-switcher";
import { UpdateBadge } from "./update-badge";

// 任务详情页保持原样：它自带头部/Tabs 与内边距，这里不再叠加全局头部和 padding。
function isFullBleed(pathname: string) {
  const p = (() => {
    try {
      return decodeURIComponent(pathname);
    } catch {
      return pathname;
    }
  })();
  // 静态导出开了 trailingSlash，列表页自身的 pathname 是 "/function/tasks/"，
  // 先去掉尾斜杠再判前缀，否则列表页会被误判成详情页而丢掉全局头部。
  const normalized = p.replace(/\/+$/, "");
  return normalized.startsWith("/function/tasks/");
}

// 현재 페이지 위치. 사이드 메뉴 설정에서 계산하므로 메뉴 이름과 항상 같다: "진단 > 작업".
// 본문에는 페이지 제목을 두지 않고 이 표시가 제목 역할을 한다.
function PageLocation({ pathname }: { readonly pathname: string }) {
  const t = useTranslations("nav");
  const trail = breadcrumbFor(pathname);
  if (trail.length === 0) return null;
  return (
    <nav aria-label="breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
      {trail.map((crumb, index) => {
        const last = index === trail.length - 1;
        const label = t(`item.${crumb.id}`);
        return (
          <span key={crumb.id} className="flex min-w-0 items-center gap-1.5">
            {index > 0 && <span className="text-muted-foreground/60">/</span>}
            {last ? (
              <span className="truncate font-semibold" aria-current="page">
                {label}
              </span>
            ) : crumb.url ? (
              <Link prefetch={false} href={crumb.url} className="truncate text-muted-foreground hover:text-foreground">
                {label}
              </Link>
            ) : (
              <span className="truncate text-muted-foreground">{label}</span>
            )}
          </span>
        );
      })}
    </nav>
  );
}

export function MainContent({ children }: { children: ReactNode }) {
  const currentUser = useCurrentUser();
  const pathname = usePathname();
  const t = useTranslations("header");
  const [version, setVersion] = useState("");

  useEffect(() => {
    api
      .health()
      .then((h) => setVersion((h.version ?? "").replace(/^v(?=\d)/, "")))
      .catch(() => setVersion(""));
  }, []);

  if (isFullBleed(pathname)) {
    return <>{children}</>;
  }

  return (
    <>
      <header
        className={cn(
          "flex h-12 shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-12",
          "[html[data-navbar-style=sticky]_&]:sticky [html[data-navbar-style=sticky]_&]:top-0 [html[data-navbar-style=sticky]_&]:z-50 [html[data-navbar-style=sticky]_&]:overflow-hidden [html[data-navbar-style=sticky]_&]:rounded-t-[inherit] [html[data-navbar-style=sticky]_&]:bg-background/50 [html[data-navbar-style=sticky]_&]:backdrop-blur-md",
        )}
      >
        <div className="flex w-full items-center justify-between gap-2 px-3">
          <div className="flex min-w-0 items-center gap-1">
            <SidebarTrigger className="-ml-1" />
            <Separator
              orientation="vertical"
              className="mx-2 data-[orientation=vertical]:h-4 data-[orientation=vertical]:self-center"
            />
            <PageLocation pathname={pathname} />
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {version && (
              <span className="font-medium text-muted-foreground text-xs tabular-nums">
                {t("version", { version })}
              </span>
            )}
            <UpdateBadge />
            <LayoutControls />
            <ThemeSwitcher />
            <AccountSwitcher users={[currentUser]} />
          </div>
        </div>
      </header>
      {/* 본문 여백은 여기 한 곳에서만 준다(p-3). 페이지는 자체 바깥 여백을 두지 않는다. */}
      <div className="min-h-0 min-w-0 flex-1 overflow-x-hidden p-3 has-data-[content-padding=false]:p-0">
        {children}
      </div>
    </>
  );
}
