# 자율 헌팅 원장 설계

ARTEX 방어 헌팅이 탐지 룰을 원장에 기록·재사용·정정하는 체계의 설계 문서. 상태: 설계안 (미구현).

## 1. 개요

* **대상**: `hunting/`, `server/hunts*.go`, `db/hunts.go`, `/defensive/hunting` 화면
* **목표**: 실행마다 달라지는 LLM 설계를 원장 룰 재사용으로 대체
* **원장 단위**: 1행 = 탐지 룰 1개. 기준 = 행위(ATT&CK 기법) × 로그 소스
* **저장 위치**: PostgreSQL 테이블 (`db/schema.sql`)
* **참고 체계**: Thaki-Siem `docs/detection-rule-expansion.md`, `docs/expansion-rules.md`
* **적용 제외**: Wazuh rule ID 대장, `wazuh-logtest`. ARTEX 로그 소스는 Splunk

| 구분 | 현재 | 변경 후 |
|---|---|---|
| 탐지 조건 | `huntDesignPrompt` 로 실행마다 생성 | 원장 룰 버전 고정 |
| 쿼리 | LLM 조사 중 생성 | 룰 유형별 템플릿으로 생성 |
| 대상 | 취약점 이름·CVE | ATT&CK 기법, CVE, 자유 주제 |
| 저장 | `defensive_hunts.result` 실행 결과 | 원장 + 버전 + 실행 기록 + 판정 |
| 중복 판정 | 없음 | 구조 지문 비교 + 샘플 재생 |
| 룰 수정 | 없음 | 수치 신호 기반 수정안 + 검증 게이트 |

## 2. 현재 구성

| 항목 | 경로 | 상태 |
|---|---|---|
| 헌팅 엔진 | `hunting/engine.go` | Research → Design → Investigate → Verify |
| 설계 생성 | `server/hunts_design.go` | LLM 호출 1회, 단계 1~4개 |
| 설계 주입 지점 | `server/hunts.go:342` `Dependencies.Design` | 함수 교체 가능 |
| 실행 기록 | `defensive_hunts` | `request`·`events`·`result` JSONB |
| 출처 해시 | `hunting.ResearchSource.SHA256` | 발췌 원문 SHA-256 |
| 필드 매핑 | `investigation.Mapping` | 13개 키 (`source_ip`, `user`, `action`, `status` 등) |
| 위협 트렌드 | `defensive_hunt_trends` | 공개 보고서 수집·자산 대조 |
| Sigma 룰 | `detections/sigma/`, `detections/sigma/correlation/` | 배포용 룰 보유 |

* **미보유 기능**: 원장, 룰 유형별 쿼리 생성, 중복 판정, 판정 집계, 주기 실행

## 3. 룰 모델

### 3.1 룰 유형

| 유형 | 판정 방식 | 인증 예시 |
|---|---|---|
| `signature` | 단건 이벤트 조건 일치 | 알려진 공격 경로 요청 |
| `event_count` | 그룹별 건수 ≥ N / 시간창 | 출발지 1개, 10분, 실패 20회 이상 |
| `value_count` | 그룹별 고유값 수 ≥ N | 출발지 1개, 30분, 계정 10개 이상 |
| `temporal` | 하위 룰 순서 발생 | 실패 N회 이후 동일 계정 성공 |
| `baseline` | 과거 분포 대비 편차 | 계정별 실패 수 30일 p99 초과 |
| `first_seen` | 최초 관측 조합 | 관리자 계정의 최초 관측 출발지 |

### 3.2 표기 형식

* **형식**: Sigma 규격 + correlation rule. 저장은 JSON 변환본
* **필드**: `investigation.Mapping` 정규화 키만 사용. 원본 필드명 금지
* **변환**: Go 내장 템플릿 6종. `pySigma` 미사용 (런타임 Python 의존 배제)
* **쿼리 결정성**: 동일 룰 버전 + 동일 매핑 = 동일 쿼리 문자열

```yaml
title: 단일 출발지 다중 로그인 실패
id: AUTH-BF-01
tags: [attack.t1110.001]
logsource: { category: authentication }
detection:
  failed: { action: failure }
  condition: failed
---
correlation:
  type: event_count
  rules: [AUTH-BF-01]
  group-by: [source_ip]
  timespan: 10m
  condition: { gte: 20 }
```

### 3.3 임계치 근거

* **산출**: 승인 시점 과거 30일 그룹별 분포의 백분위 (기본 p99)
* **기록**: 임계치, 산출 기간, 백분위, 분포 요약 → 버전 `threshold_basis`
* **수동 지정**: 허용. `threshold_basis.kind = manual` + 사유 필수

## 4. 원장 구조

### 4.1 `defensive_hunt_rules`

| 열 | 타입 | 설명 |
|---|---|---|
| `id` | BIGSERIAL | 기본 키 |
| `rule_key` | TEXT UNIQUE | `AUTH-BF-01` 형식 |
| `subject_kind` | TEXT | `technique` · `cve` · `term` |
| `subject_key` | TEXT | `T1110.001`, `CVE-2024-4577` |
| `source_profile` | TEXT | 대상 sourcetype 집합 정규화 값 |
| `rule_type` | TEXT | 3.1 유형 6종 |
| `decision` | TEXT | 5.3 판정 값 |
| `decision_ref` | BIGINT | 기존 커버·보강 시 기준 룰 `id` |
| `decision_reason` | TEXT | 수집 없음·제외 사유 |
| `status` | TEXT | `draft` · `approved` · `retired` |
| `current_version` | INT | 실행에 쓰는 버전 번호 |
| `attack_ids`, `cves` | TEXT[] | 커버리지 집계용 |

* **유일 조건**: `UNIQUE(subject_key, source_profile, rule_type)`

### 4.2 `defensive_hunt_rule_versions`

| 열 | 타입 | 설명 |
|---|---|---|
| `rule_id`, `version` | BIGINT, INT | 복합 기본 키. 행 수정·삭제 금지 |
| `rule` | JSONB | Sigma JSON 변환본 |
| `params` | JSONB | 임계치, 시간창, group-by |
| `threshold_basis` | JSONB | 3.3 근거 |
| `fingerprint` | TEXT | 5.2 구조 지문 SHA-256 |
| `samples` | JSONB | 양성·음성 샘플 이벤트 |
| `research_digest` | TEXT | 출처 `SHA256` 정렬 해시 |
| `mapping_digest` | TEXT | 승인 시점 매핑 해시 |
| `engine_version` | TEXT | `hunting.EngineVersion` |
| `origin` | TEXT | `llm_draft` · `sigma_import` · `manual` · `auto_revision` |
| `change_reason` | JSONB | 정정 신호, 근거 수치, 검증 결과 |
| `approved_by`, `approved_at` | TEXT, TIMESTAMPTZ | 자동 반영은 `system` |

### 4.3 `defensive_hunt_rule_runs`

| 열 | 타입 | 설명 |
|---|---|---|
| `id` | BIGSERIAL | 기본 키 |
| `rule_id`, `version` | BIGINT, INT | 실행한 버전 |
| `hunt_id` | BIGINT | `defensive_hunts.id` |
| `scope` | JSONB | 대상, 시간 범위 |
| `hit_groups` | INT | 탐지 묶음 수 |
| `verdicts` | JSONB | 묶음별 `정탐` · `오탐` · `미확정`, 판정 주체, 근거 참조 |
| `query_digest` | TEXT | 실행 쿼리 해시 |

* `defensive_hunts` 에 `rule_id`, `rule_version` 열 추가

## 5. 중복 판정

### 5.1 단계

앞 단계 일치 시 뒤 단계 생략.

| 단계 | 방법 | 판별 대상 |
|---|---|---|
| 1. 키 | `rule_key`, 유일 조건 조회 | 동일 대상·유형 룰 |
| 2. 지문 | 5.2 구조 지문 비교 | 조건 동일 룰, 기존 룰 하위 집합 룰 |
| 3. 재생 | 후보 양성 샘플 → 승인 룰 전체 평가 | 표현 상이·동일 반응 룰 |

### 5.2 구조 지문

* **포함**: `logsource`, 필드 조건 (필드, 연산, 정규화 값) 집합
* **포함**: correlation `type`, `group-by`, `timespan`, 조건 연산자
* **제외**: 제목, 설명, 임계치 숫자, ATT&CK 태그

### 5.3 판정 값

| 값 | 조건 | 처리 |
|---|---|---|
| `미결정` | 초안 저장 직후 | 승인 대기 |
| `신규` | 3단계 반응 룰 없음 | 룰 추가 |
| `기존 커버(<rule_key>)` | 반응 룰의 범위가 후보 이상 | 추가 없음 |
| `보강(<rule_key>)` | 반응 룰 존재, 조건·태그 부족 | 기존 룰 새 버전 |
| `수집 없음` | 필수 필드 매핑 부재 | 실행 생략, 수집 과제로 분리 |
| `제외(<사유>)` | 대상 환경 해당 없음 | 기록만 |

## 6. 자율 루프

### 6.1 단계

| 단계 | 동작 | 주체 |
|---|---|---|
| 판단 | 커버리지 빈 칸, 트렌드, 정정 신호에서 대상 선정 | 스케줄러 + LLM |
| 점검 | 승인 룰 실행. 룰 없음 → 탐색 조사 후 초안 작성 | 템플릿 / LLM |
| 기록 | 실행·탐지 묶음·판정 저장 | 서버 |
| 재사용 | 동일 대상은 승인 버전 재실행 | 서버 |
| 정정 | 7절 신호 감지 → 수정안 → 검증 게이트 | LLM + 검증기 |

### 6.2 실행 분기

1. `Term` 또는 스케줄 대상에서 `subject_key` 정규화
2. 승인 룰 존재 → 해당 버전 실행. LLM 설계 호출 없음
3. 승인 룰 없음 → 기존 Research·Design 경로로 탐색 조사
4. 탐색 조사 결과에서 룰 초안 생성 → 5절 중복 판정
5. 필수 필드 매핑 부재 → `수집 없음`
6. 탐지 묶음마다 `Verify` + LLM 해석 → `verdicts` 기록

### 6.3 LLM 역할

| 역할 | 허용 | 금지 |
|---|---|---|
| 후보 제안 | 원장 초안 행 작성 | 승인 룰 직접 수정 |
| 결과 해석 | 정상 대안 검토, 근거 연결 | 근거 없는 정탐 판정 |
| 수정안 작성 | 새 버전 초안 | 검증 게이트 생략 |

## 7. 정정

### 7.1 신호

| 신호 | 조건 | 수정 방향 |
|---|---|---|
| 오탐 과다 | 최근 10회 실행 오탐 비율 50% 초과 | 임계치 상향, 제외 조건 |
| 미탐 | 탐색 조사 근거 이벤트에 승인 룰 미반응 | 조건 확장 |
| 분포 변화 | 재산출 p99 가 기록값 대비 ±30% 초과 | 임계치 재산출 |
| 필드 변화 | `mapping_digest` 불일치, 필수 필드 부재 | `수집 없음` 전환 |
| 중복 | 두 룰이 동일 묶음에 5회 연속 동시 반응 | 병합 |

* 조건 수치는 초기값. 설정 항목으로 노출

### 7.2 검증 게이트

1. **회귀 시험**: 수정안이 기존 양성·음성 샘플 전부 통과
2. **재생 비교**: 수정 전후 버전을 동일 과거 30일에 실행, 탐지 묶음 수 차이 기록
3. **독립 검토**: 수정안 작성 호출과 분리된 LLM 호출이 원문·수정안만 받아 평가
4. **이력**: 신호, 근거 수치, 1~3 결과 → `change_reason`

### 7.3 변경 등급

#### 자동 반영 (탐지 확대)

```yaml
# AUTH-BF-01 v3 → v4
condition: { gte: 20 }   # v3
condition: { gte: 15 }   # v4
```

v3 탐지 묶음 전부가 v4 에 포함. 7.2 통과 시 `approved_by = system`.

#### 승인 대기 (탐지 축소)

```yaml
# AUTH-BF-01 v3 → v4
condition: { gte: 20 }   # v3
condition: { gte: 40 }   # v4
```

v3 탐지 묶음 일부가 v4 에서 누락. 7.2 통과 후에도 `draft` 유지, 관리자 승인 필요.

| 변경 | 등급 |
|---|---|
| 임계치 하향, 조건 추가(OR), 시간창 확대 | 자동 반영 |
| 임계치 상향, 제외 조건, 시간창 축소 | 승인 대기 |
| 룰 폐기, 병합 | 승인 대기 |
| `수집 없음` 전환 | 자동 반영 + 알림 |

### 7.4 위험과 통제

| 위험 | 통제 |
|---|---|
| 점진적 공격으로 기준선 오염 → 임계치 자동 상향 | 상향은 승인 대기 등급 |
| 수정 누적으로 원래 탐지 의도 상실 | 양성 샘플 삭제 금지, 버전 불변 |
| 로그 원문의 지시문이 LLM 수정안에 반영 | 로그·출처는 데이터로만 전달, 독립 검토 |
| 자동 실행의 쿼리 비용 | 주기당 실행 수·시간 범위 상한 |

## 8. 재검토 조건

| 조건 | 대상 | 동작 |
|---|---|---|
| `engine_version` 변경 | 전체 승인 룰 | 회귀 시험 재실행 |
| `mapping_digest` 변경 | 해당 소스 룰 | 필수 필드 재확인 |
| `research_digest` 변경 | `subject_kind = cve` 룰 | 재검토 표시 |
| Sigma 원본 갱신 | `origin = sigma_import` 룰 | 지문 재비교 |

* 재검토 표시 중에도 승인 버전 실행 유지. 결과에 경고 첨부

## 9. 커버리지 표

* **축**: ATT&CK 기법 × 로그 소스(`source_profile`)
* **칸 값**: 승인 룰 수, `수집 없음` 수, 최근 실행 시각
* **용도**: 빈 칸 = 다음 후보 선정 기준. 트렌드 보고서의 기법 ID 와 대조

## 10. 구현 순서

- [ ] 원장 테이블 3종, `db/` 조회·저장
- [ ] 구조 지문 함수, 단위 테스트
- [ ] 룰 유형별 쿼리 템플릿 6종, 결정성 테스트
- [ ] `Dependencies.Design` 주입: 승인 룰 재사용 분기
- [ ] 실행 기록·판정 저장
- [ ] 원장 목록·승인·폐기 API, `/defensive/hunting` 화면
- [ ] 탐색 조사 결과 → 룰 초안 승격
- [ ] 샘플 재생 기반 중복 판정 3단계
- [ ] 정정 신호 감지, 수정안 생성, 검증 게이트
- [ ] 주기 실행, 커버리지 표
- [ ] 시범 룰 4건: `AUTH-BF-01`, `AUTH-SPRAY-01`, `AUTH-BF-02`, `AUTH-BASE-01`

## 11. 완료 조건

- [ ] 동일 대상 2회 실행 시 `query_digest` 일치
- [ ] 승인 룰 보유 대상 실행 시 설계 LLM 호출 0회
- [ ] 지문 동일 후보의 판정 = `기존 커버`
- [ ] 양성 샘플 미통과 수정안 자동 기각
- [ ] 탐지 축소 수정안의 자동 반영 0건
- [ ] 전 버전 `change_reason` 기입, 이전 버전 복원 가능

## 12. 결정 사항

| 항목 | 결정 | 사유 |
|---|---|---|
| 탐지 축소 변경 반영 | 관리자 승인 | 미탐 비용이 오탐 비용보다 큼 (7.4) |
| 승인 권한 | 관리자 한정 | 승인 = 이후 모든 실행의 탐지 조건 확정 |
| 미승인 초안 실행 | 허용 + "미승인 설계" 표시 | 탐색 조사 경로 유지 |
| 주기 실행 간격 | 24시간 (설정 항목) | 쿼리 비용 상한. 실측 후 단축 |
| 인증 로그 필드 | `investigation.Mapping` 확장 | 3.2 정규화 키 원칙, 쿼리 결정성 |
| Sigma 공개 룰 수집 | 사용자 승인 후 사본 저장 | 외부 원본 내려받기 승인 원칙 (Thaki-Siem R0.6) |
| `detections/sigma/` 연계 | 별도 유지 | 배포용 ARTEX 지문 룰, 원장과 목적 상이 |
