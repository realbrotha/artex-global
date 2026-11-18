import type { ReactNode } from "react";

import { BrandLogo } from "@/app/(main)/_components/sidebar/app-sidebar";

// 로그인·초기 설정 화면 틀 (CLAUDE.md 1.11). neocloud 로그인과 같은 구성:
// 어두운 바탕 가운데에 로고와 폭 416px 카드.
export function AuthStage({
  title,
  description,
  children,
}: {
  readonly title: ReactNode;
  readonly description?: ReactNode;
  readonly children: ReactNode;
}) {
  return (
    <div className="flex min-h-dvh flex-col items-center justify-center gap-6 bg-stage p-4">
      {/* 어두운 바탕이라 로고는 다크 테마용을 쓴다. */}
      <div className="dark flex items-center gap-2 text-white">
        <BrandLogo />
        <span className="font-semibold text-xl">Thaki SIEM</span>
      </div>
      <div className="flex w-full max-w-[26rem] flex-col gap-6 rounded-xl border bg-card p-8 shadow-lg">
        <div className="flex flex-col gap-1.5 text-center">
          <h1 className="font-semibold text-xl">{title}</h1>
          {description && <p className="text-muted-foreground">{description}</p>}
        </div>
        {children}
      </div>
    </div>
  );
}
