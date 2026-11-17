import { DEFAULT_LOCALE, type Locale, resolveLocale } from "@/i18n/config";

import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

// 브라우저 탭 제목·검색엔진 메타 설명. layout.tsx 의 정적 metadata 로 들어가 모든
// 페이지의 <title>·<meta name="description"> 에 렌더되므로, 빌드 기본 locale 에 맞춰
// 두 언어를 분기한다. 제목은 제품명 "Thaki SIEM" 으로 모든 언어가 같다. 이 메타는 빌드 시점 정적 값이라 실행 중 언어
// 전환에는 반응하지 않는다(탭 제목 한 줄 수준이라 허용한다).
const META_BY_LOCALE: Record<Locale, { title: string; description: string }> = {
  en: {
    title: "Thaki SIEM",
    description: "A SIEM console that collects security events from Wazuh and judges them with an LLM",
  },
  ko: {
    title: "Thaki SIEM",
    description: "Wazuh 보안 이벤트를 수집하고 LLM 으로 판정하는 SIEM 콘솔",
  },
};

export const APP_CONFIG = {
  name: "ARTEX",
  version: packageJson.version,
  copyright: `© ${currentYear}, ARTEX.`,
  meta: META_BY_LOCALE[resolveLocale()] ?? META_BY_LOCALE[DEFAULT_LOCALE],
};
