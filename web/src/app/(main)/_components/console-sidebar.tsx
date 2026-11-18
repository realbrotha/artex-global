"use client";

import * as React from "react";

import Link from "next/link";

import { ChevronDownIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { breadcrumbFor } from "@/navigation/sidebar/breadcrumb";
import { areaHref, areaLinks, type NavArea, navAreas } from "@/navigation/sidebar/sidebar-items";

// 2단 메뉴 (CLAUDE.md 1.4). 왼쪽 48px 아이콘 줄(영역)과 220px 하위 메뉴가 늘 함께 보인다.
// 하위 메뉴는 사용자가 상단 바 버튼으로 접을 때만 접힌다. 크기와 색은 neocloud 의 메뉴와 같다.
export const RAIL_WIDTH = 48;
export const PANEL_WIDTH = 220;

// 현재 주소가 속한 맨 위 메뉴와, 그 메뉴의 하위 항목 중 현재 항목.
export function useActiveNav(pathname: string) {
  return React.useMemo(() => {
    const trail = breadcrumbFor(pathname);
    const top: NavArea | null = navAreas.find((area) => area.id === trail[0]?.id) ?? null;
    return { top, subId: trail[1]?.id ?? null };
  }, [pathname]);
}

// 승인 대기 건수. 5초마다 다시 읽는다.
function usePendingApprovals() {
  const [count, setCount] = React.useState(0);
  React.useEffect(() => {
    let live = true;
    const poll = async () => {
      try {
        const list = await api.interceptPending();
        if (live) setCount(list.length);
      } catch {
        /* 다음 주기에 다시 읽는다 */
      }
    };
    void poll();
    const timer = setInterval(poll, 5000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, []);
  return count;
}

function CountBadge({ count, className }: { readonly count: number; readonly className?: string }) {
  if (count === 0) return null;
  return (
    <span
      className={cn(
        "flex h-4.5 min-w-4.5 items-center justify-center rounded-full bg-warning px-1 font-semibold text-[10px] text-white leading-none",
        className,
      )}
    >
      {count > 99 ? "99+" : count}
    </span>
  );
}

const railButton =
  "relative flex size-9 items-center justify-center rounded-md text-sidebar-foreground transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
const railActive = "bg-sidebar-accent text-sidebar-accent-foreground hover:bg-sidebar-accent";

const linkClass = "flex h-9 items-center gap-2 rounded-md px-2 font-medium text-sm transition-colors hover:bg-muted";

export function ConsoleSidebar({ pathname, collapsed }: { readonly pathname: string; readonly collapsed: boolean }) {
  const t = useTranslations("nav");
  const { top, subId } = useActiveNav(pathname);
  const pending = usePendingApprovals();
  // 접은 묶음. 처음에는 모두 펼친다 (neocloud defaultOpenSections).
  const [closed, setClosed] = React.useState<ReadonlySet<string>>(new Set());
  const panel = top && !collapsed ? top : null;
  const sectionTitle = (area: NavArea, id: string) => t(id === area.id ? `item.${id}` : `section.${id}`);
  const current = panel ? areaLinks(panel).find((link) => link.id === subId) : undefined;

  const toggle = (id: string) =>
    setClosed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div
      className="flex min-h-0 shrink-0 overflow-hidden bg-sidebar transition-[width] duration-300 ease-in-out print:hidden"
      style={{ width: panel ? RAIL_WIDTH + PANEL_WIDTH : RAIL_WIDTH }}
    >
      <nav
        aria-label={t("primary")}
        className="flex h-full w-12 min-w-12 flex-col items-center gap-1 overflow-y-auto overflow-x-hidden border-r py-3"
      >
        {navAreas.map((area) => {
          const Icon = area.icon;
          const label = t(`item.${area.id}`);
          const active = top?.id === area.id;
          return (
            <Tooltip key={area.id}>
              <TooltipTrigger asChild>
                <Link
                  prefetch={false}
                  href={areaHref(area)}
                  aria-label={label}
                  className={cn(railButton, active && railActive)}
                >
                  <Icon className="size-4" aria-hidden />
                  {area.id === "config" && <CountBadge count={pending} className="-top-1 -right-1 absolute" />}
                </Link>
              </TooltipTrigger>
              <TooltipContent side="right">{label}</TooltipContent>
            </Tooltip>
          );
        })}
      </nav>
      {panel && (
        <nav
          aria-label={t(`item.${panel.id}`)}
          className="flex w-[220px] min-w-[220px] flex-col gap-4 overflow-y-auto border-r px-2 py-3"
        >
          {panel.sections.map((section) => {
            const open = !closed.has(section.id);
            const title = sectionTitle(panel, section.id);
            return (
              <div key={section.id} className="flex flex-col gap-0.5">
                {/* 묶음 제목: 이동하지 않고 묶음을 접고 편다. */}
                <button
                  type="button"
                  onClick={() => toggle(section.id)}
                  aria-expanded={open}
                  className="flex h-7 items-center justify-between rounded-md px-2 font-medium text-muted-foreground text-xs hover:text-foreground"
                >
                  {title}
                  <ChevronDownIcon className={cn("size-3.5 transition-transform", !open && "-rotate-90")} aria-hidden />
                </button>
                {open &&
                  section.items.map((link) => {
                    const LinkIcon = link.icon;
                    const active = subId === link.id;
                    return (
                      <Link
                        key={link.id}
                        prefetch={false}
                        href={link.url}
                        aria-current={active ? "page" : undefined}
                        className={cn(linkClass, active && railActive)}
                      >
                        {LinkIcon && <LinkIcon className="size-4 shrink-0" aria-hidden />}
                        <span className="min-w-0 flex-1 truncate">{t(`item.${link.id}`)}</span>
                        {link.id === "approvals" && <CountBadge count={pending} />}
                      </Link>
                    );
                  })}
              </div>
            );
          })}
          {current && (
            <span className="sr-only">
              {t("currentSection")}: {t(`item.${current.id}`)}
            </span>
          )}
        </nav>
      )}
    </div>
  );
}
