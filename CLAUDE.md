# SIEM with ARTEX 프로젝트 규칙

Go 백엔드와 Next.js 프런트엔드(`web/`)로 구성된 SIEM 콘솔의 작업 규칙.

## 1. UI 디자인 규칙

`web/src/app/(main)` 아래 모든 화면에 적용.

### 1.1 여백

* **본문 바깥 여백**: `main-content.tsx` 한 곳에서만 지정 (`p-3`). 페이지는 자체 바깥 여백을 두지 않음
* **페이지 최상위 간격**: `flex flex-1 flex-col gap-3`
* **상단 바 좌우 여백**: `px-3`
* **카드·표 안쪽 여백**: `p-3` 또는 `px-3 py-2` 이하
* **금지**: `p-4 md:p-6`, `px-4 lg:px-6`, `gap-4 md:gap-6` 처럼 화면 폭에 따라 커지는 여백
* **본문 전체 사용 화면**: `data-content-padding="false"` 지정 시 바깥 여백 0
* **폭 제한 금지**: 페이지 최상위에 `max-w-*`, `mx-auto` 를 두지 않음. 본문은 가로 폭 전체를 씀 (문단 안의 읽기 폭 제한은 허용)

### 1.2 페이지 제목

* **본문 제목 금지**: 페이지 본문에 `<h1>` 제목과 그 아래 설명 문단을 두지 않음
* **위치 표시**: 상단 바의 현재 위치 표시가 제목 역할
* **예외**: 상세 화면의 대상 이름(장비명, 작업명, 취약점명)은 본문 표시 허용
* **도구 줄**: 본문은 필터·탭 줄 또는 내용으로 바로 시작

제목 블록 제거 예)

```tsx
// 금지
<div className="flex items-start justify-between">
  <div>
    <h1 className="text-xl font-semibold">{t("title")}</h1>
    <p className="text-muted-foreground text-sm">{t("subtitle")}</p>
  </div>
  <Button>{t("refresh")}</Button>
</div>

// 허용: 제목 블록을 지우고, 남은 버튼은 아래 기존 줄로 옮김 (1.3)
```

### 1.3 한 줄 차지 금지

* **원칙**: 버튼·배지·건수 몇 개만 있는 줄을 따로 두지 않음
* **합칠 곳**: 바로 아래의 기존 줄(탭, 필터·검색 도구 줄, 요약 카드의 숫자 줄) 오른쪽 끝(`ml-auto`)
* **새로고침**: 글자 버튼 대신 아이콘 버튼(`size="icon-xs"` 또는 `icon-sm`, `aria-label` 과 `title` 지정)
* **전체 건수**: 별도 배지 줄 대신 도구 줄 끝에 `전체 N건` 문구

합치는 예)

```tsx
// 금지: 새로고침 한 줄 + 탭 한 줄
<div className="flex justify-end"><Button>{t("refresh")}</Button></div>
<div className="flex border-b">{tabs}</div>

// 허용: 탭 줄 끝에 아이콘 버튼
<div className="flex items-center border-b">
  {tabs}
  <Button variant="ghost" size="icon-sm" className="ml-auto" aria-label={t("refresh")} title={t("refresh")}>
    <RefreshCwIcon />
  </Button>
</div>
```

### 1.4 탭

* **컴포넌트**: 화면 단위 탭은 모두 `@/components/ui/tabs` 의 `Tabs` · `TabsList` · `TabsTrigger` (기본 variant). 직접 만든 버튼 묶음이나 밑줄 탭 금지
* **위치**: 본문 좌상단에서 시작. 탭 앞에 여백(`mx-*`, `ml-*`)이나 다른 요소를 두지 않음
* **같은 줄**: 검색·필터·버튼은 탭 오른쪽에 둠. 페이지 도구 버튼은 `ml-auto` 로 오른쪽 끝
* **탭과 내용 간격**: 8px 고정 (작업, 공격 표면 기준)
  * `Tabs` 가 내용을 감싸면 기본 간격(`gap-2`)만 사용. `space-y-*`, `gap-3` 이상, `TabsContent` 의 `mt-*` 금지
  * 탭 줄이 `gap-3` 페이지 열의 한 줄이면 그 줄에 `-mb-1` 을 붙여 8px 로 맞춤
* **탭 대상**: 화면에 무엇을 보여줄지 바꾸는 선택(목록 종류, 보기 방식). 묶기·정렬 같은 표 옵션은 탭이 아닌 세그먼트 버튼

```tsx
<div className="flex flex-wrap items-center gap-2">
  <Tabs value={view} onValueChange={(v) => setView(v as View)}>
    <TabsList>
      <TabsTrigger value="runs">{t("view.runs")}</TabsTrigger>
      <TabsTrigger value="judgements">{t("view.judgements")}</TabsTrigger>
    </TabsList>
  </Tabs>
  <Input className="h-8 w-64" />
  <Button variant="ghost" size="icon-sm" className="ml-auto" aria-label={t("refresh")}>
    <RefreshCwIcon />
  </Button>
</div>
```

### 1.5 상단 바 위치 표시

* **구현**: `web/src/navigation/sidebar/breadcrumb.ts` 의 `breadcrumbFor(pathname)`
* **출처**: 사이드 메뉴 설정 `sidebar-items.ts`. 표시 문구는 `nav.item.<id>` 메시지
* **형식**: 최상위 메뉴는 `인프라`, 접이식 메뉴 안의 항목은 `진단 / 작업`
* **검색 창**: 상단 바에 두지 않음

메뉴를 추가하는 절차:

1. `sidebar-items.ts` 에 항목 추가 (`id`, `url`)
2. `web/messages/*.json` 의 `nav.item.<id>` 에 이름 추가
3. 위치 표시는 자동 반영. 별도 코드 수정 없음

사이드 메뉴에 없는 화면(상세 화면 등)을 추가하는 절차:

1. `breadcrumb.ts` 의 `EXTRA_ROUTES` 에 `{ url, parent, id }` 추가. `parent` 는 소속 메뉴 항목의 `id`
2. `nav.item.<id>` 메시지 추가
3. `breadcrumb.test.ts` 통과 확인

### 1.6 가로 스크롤

* **페이지 단위 가로 스크롤 금지**: 화면 폭 1280px 이상에서 본문에 가로 스크롤이 생기지 않아야 함
* **열 폭**: 가변 열은 `minmax(0,1fr)`, 긴 문자열은 `truncate` + `title` 속성
* **표 최소 폭**: `min-w-[..]` 는 본문 가용 폭(1280px 화면에서 약 1030px = 64rem) 이하로 지정
* **넓은 표**: 불가피하면 표를 감싼 요소에만 `overflow-x-auto`. 페이지 전체가 밀리지 않게 함
* **고정 높이**: `calc(100svh - Nrem)` 사용 시 상단 바 3rem + 본문 여백 1.5rem = 4.5rem 을 기준으로 계산
* **목록·상세 패널 높이**: 화면 아래까지 늘어나야 하는 패널은 고정 높이(`h-[..px]`, `max-h-[..px]`) 대신 부모를 `h-[calc(100svh-4.5rem)]` 로 두고 `flex-1 min-h-0` 으로 채움

### 1.7 점검

화면을 추가하거나 고친 뒤 실행.

```bash
cd web && npx tsc --noEmit -p . && npm run check && npm run check:i18n && npx vitest run
```

- [ ] 본문에 `<h1>` 제목과 설명 문단이 없는가
- [ ] 버튼·배지 몇 개만 있는 줄이 없는가
- [ ] 탭이 공용 `TabsList` 이고 본문 좌상단에서 시작하는가
- [ ] 페이지 최상위에 자체 바깥 여백이 없는가
- [ ] 상단 바에 `메뉴 / 항목` 위치가 표시되는가
- [ ] 1280px 폭에서 가로 스크롤이 없는가

## 2. 문구

* **다국어**: 화면 문구는 `web/messages/{ko,en,es,ja,zh}.json` 다섯 파일에 같은 키로 추가
* **검사**: `npm run check:i18n` 으로 키 집합 일치 확인

## 3. 백엔드

* **검사**: `go vet ./server/ ./db/ ./wazuh/ && go test ./wazuh/ ./server/ ./db/`
* **포맷**: 수정한 파일에만 `gofmt -w` 적용. 디렉터리 단위 `gofmt -w` 금지 (기존 파일이 함께 바뀜)
* **스키마**: `db/schema.sql` 은 반복 실행 가능하게 작성 (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`)
* **코드·문서에 넣지 않는 값**: 실제 장비 이름, 내부 IP, 계정, 토큰
