# SIEM with ARTEX

Wazuh 경보·설정 점검 결과를 자산 관계도, 사건 후보, LLM 판정으로 보여주는 보안 관제 콘솔. [ARTEX](README.en.md)(Go 백엔드 + Next.js 프런트엔드) 포크 기반.

한국어 · [English (ARTEX)](README.en.md) · [한국어 (ARTEX 원본 설명)](README.ko.md) · [中文](README.zh.md)

## 1. 요구사항

| 항목 | 최소 버전 | 비고 |
|---|---|---|
| Go | 1.26.3 | `go.mod` 기준 |
| Node.js | 20.9 | Next.js 16 요구 버전 |
| PostgreSQL | 16 | 스키마는 기동 시 자동 적용 (`db/schema.sql`) |
| Wazuh | 4.x | manager API(55000) 필수, indexer(9200) 선택 |
| kubectl | - | Kubernetes 위 Wazuh 를 `scripts/wazuh-connect.sh` 로 연결할 때만 필요 |
| LLM API 키 | - | 사건 판정 시에만 필요 |

## 2. 설치

```bash
git clone <REPO_URL> artex-global
cd artex-global
(cd web && npm ci)
cp config.example.json config.json
```

DB 계정·데이터베이스 생성 (비밀번호는 프롬프트 입력)

```bash
createuser -P artex
createdb -O artex artex
```

`config.json` 의 `database` 항목에 위 값 기입. `ARTEX_PG_DSN` 지정 시 파일 값 무시.

## 3. 빠른 시작

1. 개발 모드 기동

   ```bash
   ./dev.sh
   ```

2. `http://localhost:3000` 접속 → `/setup` 에서 관리자 비밀번호 설정. 설정 토큰은 기동 로그의 `[auth]` 줄 참조.
3. **설정 > AI 구성 > LLM** 에서 공급자·모델 등록 (판정 기능 사용 시).
4. Wazuh 연결 등록 — 둘 중 하나

   ```bash
   scripts/wazuh-connect.sh wazuh
   ```

   * **Kubernetes 위 Wazuh**: 위 스크립트가 port-forward, 읽기 전용 Secret 조회, 연결 저장까지 수행. 실행 중 port-forward 유지, 끊기면 자동 재연결 (Ctrl-C 종료).
   * **그 외**: **설정 > 연결 > 연결 추가 > Wazuh** 에서 manager·indexer 주소와 계정 입력.
5. Thaki-Siem 탐지 입력 가져오기 (사건 후보 추출에 필요)

   ```bash
   go run ./cmd/artex -siem-import <THAKI_SIEM_DIR>
   ```

6. **자산** 에서 **새로고침** → 인프라 맵·점검 결과·사건 후보 표시 확인.

## 4. 사용법

### 4.1 인프라 맵

| 노드 | 판별 기준 |
|---|---|
| 베어메탈 | Wazuh agent, 가상화 흔적 없음 |
| VM | Wazuh agent, 가상화 감지 |
| agent 미설치 VM | 하이퍼바이저가 보고한 guest UUID 와 일치하는 agent 없음 (점선 테두리) |
| Kubernetes 클러스터 | 동일 CA 지문을 가진 장비 묶음 (상자) |
| OpenStack | `openstack-*` 역할 장비 묶음 |

* **실선**: VM 이 해당 호스트 위에서 실행 (guest UUID = VM product UUID)
* **빨간 숫자**: 수용되지 않은 취약 항목 수
* **경광등 숫자**: 사건 후보 수 (정상 판정·알려진 활동 제외)
* 노드 클릭 → 우측 패널에 점검 결과·사건 후보 표시

### 4.2 설정 점검 결과

* **출처**: indexer `wazuh-alerts-4.x-*` 의 `data.siem.check` (rule 101401–101406)
* **구분**: 취약 / 판단필요 / 오류 / 수용됨 / 양호
* **묶음**: 기준(KISA, CIS) → 항목 코드 순

### 4.3 위험 수용

**자산 > 위험 수용 > TSV 가져오기** 로 등록부 전체 교체. 다음 동기화부터 점검 수치에 반영.

```tsv
code	host	reason	approved_by	until
U-01	web01	점프 호스트 전용 root 접속	보안팀	2027-06-30
CIS 6.3.1	*	감사 로그 외부 전송으로 대체	보안팀
```

* **host**: 호스트명 또는 `*` (전체)
* **until**: 비우면 무기한. 만료일 경과 시 다시 취약으로 집계
* **CIS 코드**: `CIS `, `CIS-K8s `, `CIS-Docker ` 접두어 사용

### 4.4 사건 후보

최근 7일 경보를 상관 분석해 사건 후보 생성. Thaki-Siem `assess/events.py` 이식본.

| 패턴 | 조건 |
|---|---|
| P1 | 같은 출발지·계정의 로그인 실패 5회 이상 후 30분 내 성공 |
| P2 | 허용 대역 밖·신규 출발지·root 직접 로그인 성공 |
| P3 | 로그인 → 권한 변경 → 침입 행위 (24시간 내, 단계 간 2시간 내) |
| P4 | 방어 무력화 후 데이터 접근·흔적 삭제 |
| P5 | 자격증명 열람 후 덤프·압축·전송 |
| P6 | 한 계정에 출발지 10곳 이상 로그인 실패 |
| P7 | 한 호스트에 외부 정찰·웹 공격 요청 20건 이상 |
| P8 | 오류가 직전 일 중앙값의 5배 이상(최소 10건), sshd·sudo 비정상 종료 |
| P9 | 그 외 고위험 단일 규칙 (1시간 간격 묶음) |

* **등급**: Critical / High / Medium / Low / Info
* **알려진 활동**: 정상 업무 등록부와 일치 시 표시만 하고 집계 제외

### 4.5 LLM 판정

사건 후보 펼침 → **LLM 판정** 버튼. 목록 상단 **미판정 N건 판정** 으로 일괄 처리.

| 판정 | 의미 |
|---|---|
| breach | 침해 |
| suspicious | 의심 (정상 근거 부족 포함) |
| attempt | 시도 (성공 흔적 없음) |
| normal | 정상 업무 |
| false_positive | 오탐 |

* **전송 데이터**: 사건 요약, 타임라인(최대 50건), 인접 사건. 설정된 LLM 공급자로 전송
* **만료**: 판정 후 새 경보 발생 또는 30일 경과 시 재판정 대상
* **실행 조건**: 사용자 요청 시에만 수행. 백그라운드 자동 판정 없음

### 4.6 SIEM Log 분석

인프라 맵에서 우클릭 → **SIEM Log 분석**. 전체 장비는 탭 줄의 **전체 SIEM Log 분석** 버튼. 오른쪽 패널에 단계별 진행 표시.

| 우클릭 대상 | 분석 범위 |
|---|---|
| 장비 | 해당 장비 1대 |
| 클러스터 상자, OpenStack | 소속 장비 전체 |
| 빈 곳 | 연결의 전체 장비 |

1. 경보 수집 — 최근 7일, 대상 장비의 경보
2. 사건 후보 추출 — 4.4 의 상관 패턴 적용
3. LLM 판정 — **n건 LLM 판정** 버튼을 눌러야 시작. 미판정 사건의 경보 내용을 LLM 공급자로 전송
4. 요약 — 판정별 건수

* **저장**: 판정 결과만 저장. 분석 실행 기록은 서버 메모리에 30분 보관 후 삭제
* **범위 제한**: 장비 단위 분석은 여러 장비에 걸친 패턴(P6 등)을 일부만 탐지

## 5. 설정

### 5.1 환경 변수

| 항목 | 타입 | 기본값 | 설명 |
|---|---|---|---|
| `ARTEX_CONFIG` | 경로 | `config.json` | 설정 파일 위치 |
| `ARTEX_PG_DSN` | 문자열 | - | PostgreSQL DSN. `config.json` 보다 우선 |
| `ARTEX_SKILL_DIR` | 경로 | `skills/` | 스킬 디렉터리 |
| `ARTEX_LANG` | `ko`/`en`/`zh`/`es`/`ja` | `en` | 출력 언어 기본값 |

### 5.2 Wazuh 연결 가져오기 (`-wazuh-import`)

| 항목 | 타입 | 기본값 | 설명 |
|---|---|---|---|
| `ARTEX_WAZUH_NAME` | 문자열 | `wazuh` | 연결 이름. 같은 이름이면 갱신 |
| `ARTEX_WAZUH_MANAGER_URL` | URL | - | manager API 주소 (필수) |
| `ARTEX_WAZUH_MANAGER_USER` | 문자열 | - | manager API 계정 |
| `ARTEX_WAZUH_MANAGER_PASSWORD` | 문자열 | - | manager API 비밀번호 |
| `ARTEX_WAZUH_INDEXER_URL` | URL | - | indexer 주소. 비우면 agent 목록만 표시 |
| `ARTEX_WAZUH_INDEXER_USER` | 문자열 | - | indexer 계정 |
| `ARTEX_WAZUH_INDEXER_PASSWORD` | 문자열 | - | indexer 비밀번호 |
| `ARTEX_WAZUH_TLS_FINGERPRINT` | 문자열 | - | 서버 인증서 SHA-256 지문 고정 |
| `ARTEX_WAZUH_TLS_SKIP_VERIFY` | `true`/`false` | `false` | 인증서 검증 생략 |

* 계정 정보는 서버 키로 AES-GCM 암호화 후 DB 저장. 화면·로그 미출력

### 5.3 `scripts/wazuh-connect.sh`

| 항목 | 타입 | 기본값 | 설명 |
|---|---|---|---|
| `KUBE_CONTEXT` | 문자열 | 현재 context | kubectl context |
| `WAZUH_NS` | 문자열 | `wazuh` | Wazuh namespace |
| `API_PORT` | 숫자 | `55000` | 로컬 manager API 포트 |
| `IX_PORT` | 숫자 | `9200` | 로컬 indexer 포트 |
| `API_SECRET` | 문자열 | `siem-api-reader` | manager API 계정 Secret |
| `IX_SECRET` | 문자열 | `siem-llm-reader` | indexer 계정 Secret |
| `NO_INDEXER` | `1` | - | indexer 없이 연결 |
| `RETRY_SEC` | 숫자 | `3` | port-forward 끊김 후 재연결 대기 초 |

### 5.4 실행 플래그

| 항목 | 기본값 | 설명 |
|---|---|---|
| `-addr` | `127.0.0.1:8787` | HTTP 주소 |
| `-proxy` | `127.0.0.1:8788` | 트래픽 기록 프록시. 빈 값이면 비활성 |
| `-wazuh-import` | - | 5.2 환경 변수로 연결 등록 후 종료 |
| `-siem-import <DIR>` | - | Thaki-Siem 의 이벤트 카탈로그·판정 기준·알려진 활동·관리자 출발지·위험 수용 목록 가져온 후 종료 |
| `-accepted-risks-import <TSV>` | - | 위험 수용 목록만 교체 후 종료 |

### 5.5 고정 주기

| 항목 | 값 |
|---|---|
| 자산·점검 결과 동기화 | 5분 |
| 사건 후보 추출 | 30분 (수동 새로고침 시 즉시) |
| 경보 조회 기간 | 7일 |
| 경보 조회 상한 | 200,000건 |
| 판정 1건 시간 제한 | 3분 |

## 6. 개발 환경

```bash
go test ./wazuh/ ./db/ ./server/
```

```bash
cd web
npm run check:i18n
npx tsc --noEmit -p .
npx biome check
npx vitest run
```

사건 추출 golden 재생성 (원본 Python 결과와 비교용)

```bash
python3 wazuh/testdata/gen_golden.py <THAKI_SIEM_DIR>
```

* **백엔드 코드**: `wazuh/`, `db/wazuh_*.go`, `db/accepted_risks.go`, `db/case_verdicts.go`, `server/wazuh_sources.go`
* **화면 코드**: `web/src/app/(main)/defensive/assets/`, `web/src/lib/wazuh-api.ts`
* **문구**: `web/messages/{ko,en,es,ja,zh}.json` — 5개 언어 키 일치 필수

## 7. 문제 해결

### 7.1 백엔드 변경 미반영

* **증상**: Go 코드 수정 후 동작 변화 없음
* **원인**: `dev.sh` 의 `go run` 은 자동 재시작 미지원
* **조치**: `dev.sh` 종료 후 재실행

### 7.2 `wazuh-connect.sh` 실패

* **증상**: `wazuh-manager-master-0 조회 실패 — kube context · namespace(wazuh) 확인`
* **원인**: kubectl context 또는 namespace 불일치
* **조치**: `KUBE_CONTEXT`, `WAZUH_NS` 지정 후 재실행

### 7.3 판정 버튼이 30초 후 오류

* **증상**: 큰 사건 판정 시 `500` 응답
* **원인**: Next.js 개발 서버 프록시의 응답 시간 제한
* **조치**: 판정은 서버에서 계속 진행 후 저장. 잠시 후 **새로고침**

### 7.4 `npm ci` 후 빌드 실패

* **증상**: `Error: Cannot find module '@tailwindcss/postcss'`
* **원인**: `NODE_ENV=production` 환경에서 devDependencies 누락
* **조치**: `npm ci --include=dev`

## 8. ARTEX 원본 기능

* 자율 침투 테스트 에이전트, 취약점·자산 그래프, 트래픽 기록 등 원본 기능 유지
* 설명: [README.en.md](README.en.md), [README.ko.md](README.ko.md)
* 방어·탐지 자료: [docs/defense-ko.md](docs/defense-ko.md)

## 9. 라이선스

* **라이선스**: AGPL-3.0 ([LICENSE](LICENSE))
* **원본**: [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX), [jiwoochris/artex-global](https://github.com/jiwoochris/artex-global)
* **사용 제한**: 소유하거나 서면 허가를 받은 시스템에서만 사용. 전체 고지는 [README.ko.md](README.ko.md#️-먼저-읽어-주세요--사용-범위와-국내법-고지)
