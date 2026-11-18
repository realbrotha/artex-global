# Thaki SIEM 프로젝트 규칙

Go 백엔드와 Next.js 프런트엔드(`web/`)로 구성된 SIEM 콘솔의 작업 규칙.

## 1. UI 디자인 규칙

* **기준**: `ThakiCloud/neocloud` 의 `DESIGN.md`, `frontend/apps/neocloud/src/app/neocloud-theme.css`
* **적용 범위**: `web/src/app/(main)` 아래 모든 화면, `web/src/components`
* **구현 방식**: neocloud 공용 패키지(`@ThakiCloud/shared`) 대신 shadcn/ui 컴포넌트에 같은 수치 적용
* **공통 조각**: `web/src/components/page.tsx` (`PageHeader`, `DetailHeader`, `TableSkeletonRows`, `ListEmpty`, `LoadError`, `DrawerFooter`, `useConfirm`)
* **자동 검사**: `npm run check:ui` (`web/src/scripts/check-ui-rules.ts`). CI 머지 조건
* **규칙 변경**: 이 장과 검사 스크립트를 같은 커밋에서 수정

### 1.1 색

| 토큰 | 라이트 | 다크 | 용도 |
|---|---|---|---|
| `primary` | `#6c5cf2` | `#6c5cf2` (글자 `#9b8cfb`) | 주 작업 버튼, 선택 상태, 링크 |
| `content` | `#f7f7f7` | `#0f0f12` | 본문 바탕 |
| `card` / `background` | `#ffffff` | `#18181b` | 카드, 표, 상단 바 |
| `sidebar` | `#ffffff` | `#1e1e22` | 메뉴 |
| `canvas` | `#f0f2f7` | `#0b0b0e` | 지도·그래프 바탕 |
| `muted-foreground` | `#606f85` | `#a1a1aa` | 보조 글자 |
| `danger` | `#dc2626` | `#f87171` | 실패, 차단, 심각 |
| `caution` | `#ea580c` | `#fb923c` | 높음 |
| `warning` | `#d97706` | `#fbbf24` | 대기, 주의, 중간 |
| `success` | `#16a34a` | `#4ade80` | 완료, 정상 |
| `info` | `#2563eb` | `#60a5fa` | 진행 중, 안내 |

* **정의 위치**: `web/src/app/globals.css` 한 곳
* **화면 코드**: 토큰 클래스만 사용 (`bg-primary`, `text-danger`, `bg-success/10`, `border-warning/50`)
* **금지**: Tailwind 팔레트 색(`text-red-600`, `bg-emerald-500`), 색 값(`#6c5cf2`, `rgb()`), `dark:` 색 클래스
* **상태 색**: `web/src/lib/status.ts` 의 tone 으로 지정. 색은 상태·심각도 표시에만 사용
* **분류 표시**: 종류·범위·출처는 색 없는 글자
* **지도·그래프**: 바탕은 `bg-canvas`, 노드는 `bg-card`. CSS 클래스를 못 쓰는 캔버스 라이브러리(G6)는 라이트·다크 값을 모두 정의하고 테마 변경 시 다시 그림 (`coverage-graph-tab.tsx` 의 `GRAPH_TONE`)
* **예외**: 그래프 계열 색(`asset-graph.tsx`, `coverage-graph-tab.tsx`, `exploration-graph.tsx`), 로고(`brand-mark.tsx`). 범례·숫자 함께 표시

### 1.2 글꼴·글자 크기

* **글꼴**: 영문 Mona Sans v2.0.27, 한글 Pretendard v1.3.9 (`web/public/fonts`, OFL-1.1). 한글만 굵기 +50 보정
* **글꼴 선택**: 없음. 테마는 라이트·다크·시스템 3개
* **본문**: 14px (`text-sm`). 보조 12px (`text-xs`)
* **최대**: 20px (`text-xl`). `text-2xl` 이상 금지
* **페이지 제목**: 20px semibold (`PageHeader`, `DetailHeader` 가 표시)

### 1.3 컨트롤 높이

| `size` | 높이 | 용도 |
|---|---|---|
| `default`, `sm` | 36px | 기본 버튼, 도구 줄 |
| `lg` | 40px | 로그인 등 단독 주 버튼 |
| `xs` | 32px | 상세 머리 작업 버튼, 표 안 버튼 |
| `icon`, `icon-sm` | 36px | 아이콘 버튼 |
| `icon-xs` | 32px | 상단 바, 표 안 아이콘 버튼 |

* **입력·선택**: `Input`, `SelectTrigger` 36px
* **금지**: 페이지에서 `h-7`, `h-8` 로 컨트롤 높이 재지정. `size` 로 조정

### 1.4 콘솔 틀

* **구현**: `web/src/app/(main)/_components/main-content.tsx`, `console-sidebar.tsx`
* **상단 바**: 44px (`h-11`). 왼쪽 로고 칸은 메뉴 폭과 일치. 오른쪽 버전·업데이트·테마·계정
* **메뉴**: 48px 아이콘 줄(영역) + 220px 하위 메뉴(묶음 제목 + 항목). 화면 이동 단계는 최대 2단
* **메뉴 출처**: `web/src/navigation/sidebar/sidebar-items.ts` 의 `navAreas`. 이름은 `nav.item.<id>`, 묶음 제목은 `nav.section.<id>`

| 영역 (아이콘 줄) | 하위 메뉴 묶음 |
|---|---|
| 홈 | 홈: 대시보드, 대화 |
| 보안 관제 | 보안 관제: 인프라, 이벤트 탐지, 설정 점검, 위협 헌팅 |
| 진단 | 진단: 작업, 공격 표면, 취약점, 트래픽 |
| 활동 기록 | 활동 기록: 분석 이력, 탐지 품질, 도구 실행, LLM 기록, 작업 공간, 로그 |
| 설정 | 수집: 연결, 분석 스케줄 / AI: LLM, 에이전트, 스킬, 도구, MCP / 차단·승인: 가로채기 규칙, 자산 차단, 승인 기록 / 시스템: 알림 발송, 시스템 설정 |

#### 아이콘 줄

* **항목**: 큰 영역만. 모든 영역은 하위 메뉴를 가짐 (화면으로 바로 가는 영역 없음)
* **표시**: 16px 아이콘 + 마우스를 올리면 이름. 36px 버튼, 간격 4px
* **클릭**: 하위 메뉴의 첫 항목으로 이동
* **선택 표시**: 보라 옅은 바탕(`bg-sidebar-accent`) + 진한 보라 글자

#### 하위 메뉴

* **표시**: 항상 펼침. 메뉴 폭 268px(48 + 220) 고정. 화면을 옮겨도 폭이 바뀌지 않음
* **접기**: 사용자가 상단 바 왼쪽 버튼으로 접을 때만 접힘. 브라우저 세션 동안 유지
* **neocloud 와 차이**: neocloud 는 홈에서 아이콘 줄만 표시. SIEM 은 홈에도 하위 메뉴를 둠
* **묶음 제목**: 12px 회색, 클릭하면 그 묶음만 접고 폄 (이동 없음). 처음에는 모두 펼침
* **묶음이 하나인 영역**: 묶음 id 를 영역 id 와 같게 두고 제목은 영역 이름
* **묶음 나누기**: 한 영역의 항목이 8개를 넘으면 묶음을 나눔. 한 묶음은 8개 이하
* **항목**: 36px, 16px 아이콘 + 이름. 선택 표시는 아이콘 줄과 같음
* **건수 배지**: 승인 대기 건수를 설정 아이콘과 `승인 기록` 항목에 표시
* **메뉴에 없는 화면**(상세 등): `EXTRA_ROUTES` 의 `parent` 항목을 선택 상태로 표시
* **스크린 리더**: `현재 섹션: <항목 이름>` 숨김 글자
* **검사**: `breadcrumb.test.ts` (모든 영역에 하위 메뉴, 묶음당 8개 이하, 모든 항목의 위치 계산)

메뉴 추가 절차:

1. `sidebar-items.ts` 의 알맞은 영역·묶음에 항목 추가 (`id`, `url`, `icon`)
2. `web/messages/*.json` 의 `nav.item.<id>` 에 이름 추가. 새 묶음이면 `nav.section.<id>` 도 추가
3. 하위 메뉴·페이지 제목 자동 반영
4. `breadcrumb.test.ts` 통과 확인

사이드 메뉴에 없는 화면(상세 화면 등) 추가 절차:

1. `breadcrumb.ts` 의 `EXTRA_ROUTES` 에 `{ url, parent, id }` 추가. `parent` 는 소속 메뉴 항목의 `id`
2. `nav.item.<id>` 메시지 추가
3. `breadcrumb.test.ts` 통과 확인

### 1.5 본문 틀

* **지정 위치**: `main-content.tsx` 한 곳
* **폭**: 최대 1400px (`max-w-[87.5rem]`), 가운데 정렬
* **여백**: 좌우 32px (`px-8`), 위 24px (`pt-6`), 아래 80px (`pb-20`)
* **페이지 최상위**: `flex flex-col gap-4`. 자체 바깥 여백, `max-w-*`, `mx-auto` 금지
* **화면 아래까지 채우는 페이지**: 최상위에 `data-page-fill` 과 `min-h-0 flex-1`. 늘어나는 패널은 `min-h-0 flex-1`
* **고정 옆 패널**: `sticky top-6 h-[calc(var(--main-h)-3rem)]`
* **금지**: `100svh`, `100vh` 계산. `md:p-6` 처럼 화면 폭에 따라 커지는 여백
* **본문 전체 사용 화면**(대화): 최상위에 `data-content-padding="false"`. 여백·폭 제한 없음

가로 넘침:

* **지원 폭**: 1280px 이상. 1024px 에서도 본문 가로 스크롤 없음
* **열 폭**: 가변 열은 `minmax(0,1fr)`, 긴 문자열은 `truncate` + `title`
* **넓은 표**: 표를 감싼 요소에만 `overflow-x-auto`

### 1.6 페이지 머리

* **목록·설정 화면**: `PageHeader` 로 시작. 제목은 메뉴 이름 자동, 주 작업 버튼(만들기, 추가)은 `actions`
* **상세 화면**: `DetailHeader` 로 시작 (1.8)
* **금지**: 제목 아래 설명 문단, 화면 코드의 `<h1>`
* **한 줄 차지 금지**: 버튼·배지만 있는 줄을 따로 두지 않음. 보조 버튼은 도구 줄 끝(`ml-auto`)
* **새로고침**: 아이콘 버튼 (`variant="ghost" size="icon-sm"`, `aria-label`, `title`)

```tsx
<div className="flex flex-col gap-4">
  <PageHeader actions={<Button onClick={openCreate}><PlusIcon />{t("create")}</Button>} />
  <div className="flex flex-wrap items-center gap-2">
    <Input className="w-80" placeholder={t("search")} />
    <Button variant="ghost" size="icon-sm" className="ml-auto" aria-label={t("refresh")} title={t("refresh")}>
      <RefreshCwIcon />
    </Button>
  </div>
  <Table>...</Table>
  <TablePagination page={page} total={total} onPageChange={setPage} />
</div>
```

### 1.7 목록

1. `PageHeader`
2. 탭 (있을 때)
3. 도구 줄: 검색(320px, `w-80`) · 필터 · 필터 지우기 · 끝에 보조 버튼
4. 표 또는 카드 격자
5. 쪽 번호 (`TablePagination`, 목록 아래 오른쪽)

* **쪽 크기**: 12 (`PAGE_SIZE`). 행 수 선택 없음
* **로딩**: 표 뼈대 3줄 (`TableSkeletonRows`). 가운데 스피너, 빈 표 금지
* **결과 없음·필터 결과 없음**: `ListEmpty`
* **읽기 실패**: `LoadError` + 다시 시도 버튼
* **행 작업**: 마지막 열의 `...` 메뉴 (`DropdownMenu`). 위험 작업 앞에 구분선, `text-danger`
* **표 머리**: 14px

### 1.8 상세

* **머리 카드**: `DetailHeader` (경로 `목록 › 이름`, 이름, 상태 배지, 작업 버튼)
* **작업 버튼**: `variant="outline" size="xs"` (32px). 위험 작업은 `className="text-danger"`
* **탭**: 머리 카드 아래 `Tabs`. 선택한 탭 내용만 렌더
* **내용**: 카드 단위 (`rounded-xl border bg-card`)

### 1.9 만들기·수정·확인

* **만들기·수정·관리**: 오른쪽 드로어 `Sheet`
  * `size="sm"` 480px: 짧은 단일 열 폼
  * `size="md"` 720px: 긴 폼, 여러 구역, 목록
  * 드로어에 폭·높이·`overflow` 클래스 추가 금지
* **드로어 하단**: `DrawerFooter` (가운데, 같은 폭의 취소·확인)
* **가운데 `Dialog`**: 목록에서 하나 고르는 창, 보기 전용 창에만 사용
* **위험 작업**(삭제, 중지, 되돌리기): `useConfirm()` 확인 창. 결과와 대상 이름 명시. `window.confirm` 금지
* **오류 표시**: 칸 오류는 해당 칸 아래. 서버 오류는 폼 위 `Alert`. toast 는 저장 성공에만 사용

```tsx
const confirm = useConfirm();
if (!(await confirm({ title: t("deleteTitle", { name }), description: t("deleteBody"), destructive: true }))) return;
```

### 1.10 탭

* **컴포넌트**: `@/components/ui/tabs` 의 `Tabs` · `TabsList` · `TabsTrigger` (기본 variant). 직접 만든 버튼 묶음·밑줄 탭 금지
* **위치**: `PageHeader` 바로 아래 줄 왼쪽 끝. 검색·필터·버튼은 탭 오른쪽
* **탭과 내용 간격**: 8px
  * `Tabs` 가 내용을 감싸면 기본 간격(`gap-2`)만 사용. `space-y-*`, `TabsContent` 의 `mt-*` 금지
  * 탭 줄이 `gap-4` 페이지 열의 한 줄이면 그 줄에 `-mb-2`
* **탭 대상**: 보여줄 대상을 바꾸는 선택(목록 종류, 보기 방식). 묶기·정렬은 세그먼트 버튼(`ToggleGroup`)

### 1.11 로그인·초기 설정

* **구현**: `web/src/app/(auth)/_components/auth-stage.tsx`
* **구성**: 어두운 바탕(`bg-stage`, 두 테마 공통) 가운데에 로고 + `Thaki SIEM` + 폭 416px 카드
* **카드**: 제목 20px, 설명 한 줄, 폼. 콘솔 틀(메뉴·상단 바) 없음

### 1.12 점검

화면을 추가하거나 고친 뒤 실행.

```bash
cd web && npx tsc --noEmit -p . && npm run check && npm run check:i18n && npm run check:ui && npx vitest run
```

- [ ] `npm run check:ui` 통과
- [ ] 페이지가 `PageHeader` 또는 `DetailHeader` 로 시작하는가
- [ ] 만들기·수정이 오른쪽 드로어이고 하단이 `DrawerFooter` 인가
- [ ] 목록 로딩·빈 결과·오류가 `TableSkeletonRows` · `ListEmpty` · `LoadError` 인가
- [ ] 1024px · 1280px · 1440px 에서 가로 스크롤이 없는가 (화면 확인)
- [ ] 라이트·다크 테마 모두 글자가 읽히는가 (화면 확인)

## 2. 문구

* **다국어**: 화면 문구는 `web/messages/{ko,en}.json` 두 파일에 같은 키로 추가. 지원 언어는 한국어·영어 2개
* **검사**: `npm run check:i18n` 으로 키 집합 일치 확인

## 3. 백엔드

* **검사**: `go vet ./server/ ./db/ ./wazuh/ && go test ./wazuh/ ./server/ ./db/`
* **포맷**: 수정한 파일에만 `gofmt -w` 적용. 디렉터리 단위 `gofmt -w` 금지 (기존 파일이 함께 바뀜)
* **스키마**: `db/schema.sql` 은 반복 실행 가능하게 작성 (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`)
* **코드·문서에 넣지 않는 값**: 실제 장비 이름, 내부 IP, 계정, 토큰
