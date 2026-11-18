"use client";

import { type ReactNode, useEffect, useState } from "react";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { PanelLeftIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { ConfirmProvider } from "@/components/page";
import { Button } from "@/components/ui/button";
import { useCurrentUser } from "@/hooks/use-current-user";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

import { ConsoleSidebar, PANEL_WIDTH, RAIL_WIDTH, useActiveNav } from "./console-sidebar";
import { AccountSwitcher } from "./sidebar/account-switcher";
import { BrandLogo } from "./sidebar/app-sidebar";
import { ThemeSwitcher } from "./sidebar/theme-switcher";
import { UpdateBadge } from "./update-badge";

const PANEL_KEY = "siem_nav_panel_collapsed";

// 콘솔 틀 (CLAUDE.md 1.4, 1.5). neocloud 와 같은 구성:
// 44px 상단 바 / 48px 아이콘 줄 + 220px 하위 메뉴 / 본문은 가운데 1400px.
export function MainContent({ children }: { children: ReactNode }) {
  const currentUser = useCurrentUser();
  const pathname = usePathname();
  const t = useTranslations("header");
  const [version, setVersion] = useState("");
  // 하위 메뉴 접힘은 브라우저 세션 동안만 기억한다. 아이콘 줄은 접히지 않는다.
  const [collapsed, setCollapsed] = useState(false);
  const { top } = useActiveNav(pathname);
  const hasPanel = top !== null;
  const panelOpen = hasPanel && !collapsed;

  useEffect(() => {
    api
      .health()
      .then((h) => setVersion((h.version ?? "").replace(/^v(?=\d)/, "")))
      .catch(() => setVersion(""));
    try {
      setCollapsed(sessionStorage.getItem(PANEL_KEY) === "1");
    } catch {
      /* 저장소를 못 쓰면 펼친 채로 둔다 */
    }
  }, []);

  const togglePanel = () => {
    setCollapsed((value) => {
      try {
        sessionStorage.setItem(PANEL_KEY, value ? "0" : "1");
      } catch {
        /* 무시 */
      }
      return !value;
    });
  };

  return (
    <ConfirmProvider>
      <div className="flex h-svh flex-col overflow-hidden bg-background text-foreground print:h-auto print:overflow-visible">
        <header className="flex h-11 min-h-11 w-full shrink-0 print:hidden">
          <div
            className="flex h-11 shrink-0 items-center border-r border-b bg-sidebar transition-[width] duration-300 ease-in-out"
            style={{ width: panelOpen ? RAIL_WIDTH + PANEL_WIDTH : RAIL_WIDTH }}
          >
            <Link
              prefetch={false}
              href="/dashboard"
              aria-label="Thaki SIEM"
              className="flex h-11 w-12 min-w-12 items-center justify-center"
            >
              <BrandLogo />
            </Link>
            {panelOpen && <span className="min-w-0 flex-1 truncate px-1 font-semibold text-sm">Thaki SIEM</span>}
          </div>
          <div className="flex min-w-0 flex-1 items-center justify-between gap-2 border-b bg-background px-3">
            <div className="flex min-w-0 items-center gap-1">
              {hasPanel && (
                <Button
                  variant="ghost"
                  size="icon-xs"
                  onClick={togglePanel}
                  aria-label={t(collapsed ? "expandMenu" : "collapseMenu")}
                  title={t(collapsed ? "expandMenu" : "collapseMenu")}
                >
                  <PanelLeftIcon />
                </Button>
              )}
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {version && (
                <span className="font-medium text-muted-foreground text-xs tabular-nums">
                  {t("version", { version })}
                </span>
              )}
              <UpdateBadge />
              <ThemeSwitcher />
              <AccountSwitcher users={[currentUser]} />
            </div>
          </div>
        </header>
        <div className="flex min-h-0 flex-1">
          <ConsoleSidebar pathname={pathname} collapsed={collapsed} />
          <main className="min-w-0 flex-1 overflow-auto bg-content print:overflow-visible">
            {/* 본문 틀은 여기 한 곳에서만 정한다. 페이지는 자체 바깥 여백·폭 제한을 두지 않는다. */}
            <div
              className={cn(
                "mx-auto flex min-h-full min-w-0 max-w-[87.5rem] flex-col px-8 pt-6 pb-20",
                // 화면 아래까지 채우는 페이지(data-page-fill): 높이를 본문에 맞추고 아래 여백을 줄인다.
                "has-data-page-fill:h-full has-data-page-fill:pb-6",
                // 본문 전체를 쓰는 화면(대화 등): 여백과 폭 제한 없음.
                "has-data-[content-padding=false]:h-full has-data-[content-padding=false]:max-w-none has-data-[content-padding=false]:p-0",
              )}
            >
              {children}
            </div>
          </main>
        </div>
      </div>
    </ConfirmProvider>
  );
}
