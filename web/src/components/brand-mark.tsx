import * as React from "react";

import { cn } from "@/lib/utils";

// 육각 경계(보호 대상 인프라) 안을 레이더가 쓸고 지나가며 이벤트 하나(주황 점)를 잡아내는 모양.
// 외곽선과 중심은 currentColor 라 라이트·다크 테마 모두 글자색을 따른다.
export function BrandMark({ className, ...props }: React.SVGProps<SVGSVGElement>) {
  const id = React.useId();
  const sweep = `${id}-sweep`;
  return (
    <svg
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("shrink-0", className)}
      {...props}
    >
      <title>SIEM</title>
      <defs>
        <linearGradient id={sweep} x1="16" y1="16" x2="23" y2="7" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#22d3ee" stopOpacity="0" />
          <stop offset="1" stopColor="#22d3ee" stopOpacity="0.85" />
        </linearGradient>
      </defs>
      {/* 경계 */}
      <path
        d="M16 2.8 27.4 9.4v13.2L16 29.2 4.6 22.6V9.4Z"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      {/* 관측 반경 */}
      <circle cx="16" cy="16" r="5.2" stroke="currentColor" strokeOpacity="0.3" strokeWidth="1.2" />
      {/* 레이더 부채꼴과 선두선 */}
      <path d="M16 16V6a10 10 0 0 1 9.4 6.58Z" fill={`url(#${sweep})`} />
      <path d="M16 16l9.4-3.42" stroke="#22d3ee" strokeWidth="1.6" strokeLinecap="round" />
      {/* 탐지된 이벤트 */}
      <circle cx="20.8" cy="10.3" r="3.1" stroke="#f97316" strokeOpacity="0.45" strokeWidth="1" />
      <circle cx="20.8" cy="10.3" r="1.8" fill="#f97316" />
      <circle cx="16" cy="16" r="1.7" fill="currentColor" />
    </svg>
  );
}
