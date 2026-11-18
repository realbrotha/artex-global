// UI 규칙 자동 검사 (CLAUDE.md 1장). 규칙을 바꾸면 CLAUDE.md 와 이 파일을 같은 커밋에서 고친다.
// 실행: npm run check:ui
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = join(__dirname, "..", "..");
const SRC = join(ROOT, "src");

interface Rule {
  id: string;
  doc: string;
  pattern: RegExp;
  // 검사할 파일 (ROOT 기준 상대 경로)
  scope: (file: string) => boolean;
  // 예외 파일 (ROOT 기준 상대 경로)
  allow?: readonly string[];
}

const PALETTE =
  "(?:red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|slate|gray|zinc|neutral|stone)";
const COLOR_PREFIX = "(?:bg|text|border(?:-[trblxy])?|ring|fill|stroke|from|to|via|outline|divide|shadow|decoration)";

const isScreen = (f: string) =>
  f.startsWith("src/app/") || (f.startsWith("src/components/") && !f.startsWith("src/components/ui/"));
const isMain = (f: string) => f.startsWith("src/app/(main)/");
const isMainPage = (f: string) => isMain(f) && f.endsWith("/page.tsx");
const notTest = (f: string) => !/\.test\.tsx?$/.test(f);

const RULES: Rule[] = [
  {
    id: "palette-color",
    doc: "1.1 Tailwind 팔레트 색 금지. 토큰(primary·danger·caution·warning·success·info·muted) 사용",
    pattern: new RegExp(`(?<![\\w-])${COLOR_PREFIX}-${PALETTE}-\\d{2,3}\\b`),
    scope: (f) => (isScreen(f) || f.startsWith("src/lib/")) && notTest(f),
  },
  {
    id: "raw-color",
    doc: "1.1 색 값 직접 사용 금지. globals.css 토큰 사용",
    pattern: /#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b(?![\w-])|\brgba?\(/,
    scope: (f) => isScreen(f) && f.endsWith(".tsx") && notTest(f),
    // 그래프 계열 색과 로고만 예외 (범례·숫자 함께 표시)
    allow: [
      "src/components/brand-mark.tsx",
      "src/components/exploration-graph.tsx",
      "src/app/(main)/defensive/assets/_components/asset-graph.tsx",
      "src/app/(main)/function/tasks/detail/_tabs/coverage-graph-tab.tsx",
    ],
  },
  {
    id: "text-size",
    doc: "1.2 화면 글자 20px(text-xl) 이하",
    pattern: /(?<![\w-])text-(?:2xl|3xl|4xl|5xl|6xl|7xl|8xl|9xl)\b|text-\[(?:2[1-9]|[3-9]\d)px\]/,
    scope: (f) => isScreen(f) && notTest(f),
  },
  {
    id: "control-height",
    doc: "1.3 버튼·입력·선택 높이를 페이지에서 다시 지정하지 않음 (기본 36px, size 로 조정)",
    pattern: /<(?:Button|Input|SelectTrigger)\b[^>]*?className=(?:"|\{cn\(")[^"]*(?<![\w-])h-(?:5|6|7|8)\b/,
    scope: (f) => isScreen(f) && notTest(f),
  },
  {
    id: "viewport-calc",
    doc: "1.5 100svh·100vh 계산 금지. data-page-fill 또는 var(--main-h) 사용",
    pattern: /100(?:s|d)?vh/,
    scope: (f) => isMain(f) && notTest(f),
  },
  {
    id: "responsive-padding",
    doc: "1.5 화면 폭에 따라 커지는 바깥 여백 금지",
    pattern: /(?<![\w-])(?:sm|md|lg|xl):(?:p|px|py|gap)-\d/,
    scope: (f) => isMain(f) && notTest(f),
  },
  {
    id: "page-max-width",
    doc: "1.5 본문 폭은 main-content 에서만 지정 (max-w-screen-*, container 금지)",
    pattern: /(?<![\w@-])(?:max-w-screen-\w+|container)(?![\w:-])/,
    scope: (f) => isMain(f) && notTest(f),
  },
  {
    id: "page-header",
    doc: '1.6 페이지는 PageHeader 또는 DetailHeader 로 시작 (본문 전체 사용 화면은 data-content-padding="false")',
    pattern: /^(?![\s\S]*(?:<PageHeader\b|<DetailHeader\b|data-content-padding="false"|redirect\())[\s\S]*$/,
    scope: isMainPage,
  },
  {
    id: "raw-heading",
    doc: "1.6 페이지 제목은 PageHeader·DetailHeader 가 그림. 화면 코드에 <h1> 금지",
    pattern: /<h1\b/,
    scope: (f) => isMain(f) && notTest(f),
  },
  {
    id: "window-confirm",
    doc: "1.9 window.confirm 금지. useConfirm() 사용",
    pattern: /\bwindow\.confirm\(|(?<![\w.])confirm\(\s*[`"'t]/,
    scope: (f) => isScreen(f) && notTest(f),
  },
  {
    id: "sheet-width",
    doc: "1.9 드로어 폭·높이는 SheetContent size(sm·md)로만 지정",
    pattern:
      /<SheetContent\b[^>]*?className=(?:"|\{cn\(")[^"]*(?<![\w-])(?:max-w-|w-\[|w-\d|sm:max-w|md:max-w|lg:max-w|max-h-|overflow-)/,
    scope: (f) => isScreen(f) && notTest(f),
  },
  {
    id: "old-sidebar",
    doc: "1.4 콘솔 틀은 main-content·console-sidebar. shadcn Sidebar 사용 금지",
    pattern: /from "@\/components\/ui\/sidebar"/,
    scope: (f) => isScreen(f) && notTest(f),
  },
];

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, out);
    else if (/\.(tsx?|css)$/.test(name)) out.push(path);
  }
  return out;
}

let failures = 0;
const files = walk(SRC).map((p) => relative(ROOT, p));
for (const rule of RULES) {
  for (const file of files) {
    if (!rule.scope(file) || rule.allow?.includes(file)) continue;
    const text = readFileSync(join(ROOT, file), "utf8");
    if (rule.id === "page-header") {
      if (rule.pattern.test(text)) {
        console.error(`${file}: [${rule.id}] ${rule.doc}`);
        failures++;
      }
      continue;
    }
    // JSX 태그가 여러 줄에 걸치므로 태그 단위 규칙은 줄바꿈을 공백으로 바꿔 검사한다.
    const multiline = rule.id === "control-height" || rule.id === "sheet-width";
    const lines = multiline ? [text.replace(/\s*\n\s*/g, " ")] : text.split("\n");
    lines.forEach((line, index) => {
      if (/ui-rules-ignore/.test(line)) return;
      const match = line.match(rule.pattern);
      if (match) {
        const where = multiline ? "" : `:${index + 1}`;
        console.error(`${file}${where}: [${rule.id}] ${rule.doc} — ${match[0].slice(0, 80)}`);
        failures++;
      }
    });
  }
}

if (failures > 0) {
  console.error(`\nUI 규칙 위반 ${failures}건. CLAUDE.md 1장 참고.`);
  process.exit(1);
}
console.log(`UI 규칙 검사 통과 (${files.length}개 파일, 규칙 ${RULES.length}개)`);
