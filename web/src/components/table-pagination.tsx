"use client";

import { useEffect, useRef } from "react";

import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import { Pagination, PaginationContent, PaginationEllipsis, PaginationItem } from "@/components/ui/pagination";

// 목록 한 쪽의 행 수 (CLAUDE.md 1.7). 행 수 선택은 두지 않는다.
export const PAGE_SIZE = 12;

interface TablePaginationProps {
  page: number; // 1-based
  pageSize?: number;
  total: number; // total (after filtering)
  onPageChange: (p: number) => void;
}

// pageWindows returns the sequence of page numbers / ellipsis to render.
function pageWindows(page: number, total: number): (number | "...")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const out: (number | "...")[] = [1];
  if (page > 3) out.push("...");
  const lo = Math.max(2, page - 1);
  const hi = Math.min(total - 1, page + 1);
  for (let i = lo; i <= hi; i++) out.push(i);
  if (page < total - 2) out.push("...");
  out.push(total);
  return out;
}

export function TablePagination({ page, pageSize = PAGE_SIZE, total, onPageChange }: TablePaginationProps) {
  const t = useTranslations("pagination");
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const from = total === 0 ? 0 : (safePage - 1) * pageSize + 1;
  const to = Math.min(safePage * pageSize, total);
  const onPageChangeRef = useRef(onPageChange);
  onPageChangeRef.current = onPageChange;

  useEffect(() => {
    if (page !== safePage) onPageChangeRef.current(safePage);
  }, [page, safePage]);

  return (
    // 목록 아래 오른쪽: 건수 문구 + 쪽 번호 (neocloud CountedPagination 과 같은 배치).
    <div className="flex flex-wrap items-center justify-end gap-3 pt-3">
      <span className="text-muted-foreground text-sm tabular-nums">
        {total > 0 ? t("range", { from, to, total }) : t("empty")}
      </span>

      {totalPages > 1 && (
        <Pagination className="mx-0 w-auto justify-end">
          <PaginationContent>
            <PaginationItem>
              <Button
                variant="ghost"
                size="icon-sm"
                disabled={safePage === 1}
                onClick={() => onPageChange(safePage - 1)}
                aria-label={t("prev")}
              >
                <ChevronLeftIcon className="size-4" />
              </Button>
            </PaginationItem>
            {pageWindows(safePage, totalPages).map((p, i) =>
              p === "..." ? (
                <PaginationItem key={`el-${i}`}>
                  <PaginationEllipsis />
                </PaginationItem>
              ) : (
                <PaginationItem key={p}>
                  <Button
                    variant={p === safePage ? "outline" : "ghost"}
                    size="icon-sm"
                    onClick={() => onPageChange(p)}
                    aria-current={p === safePage ? "page" : undefined}
                  >
                    {p}
                  </Button>
                </PaginationItem>
              ),
            )}
            <PaginationItem>
              <Button
                variant="ghost"
                size="icon-sm"
                disabled={safePage === totalPages}
                onClick={() => onPageChange(safePage + 1)}
                aria-label={t("next")}
              >
                <ChevronRightIcon className="size-4" />
              </Button>
            </PaginationItem>
          </PaginationContent>
        </Pagination>
      )}
    </div>
  );
}
