# IDOR Scout

[English](README.md) | 한국어

`IDOR Scout`는 OpenAPI(JSON) 기반 후보 추출, 2계정 교차 검증, Playwright 브라우저 컨텍스트 재검증을 결합해 IDOR(Insecure Direct Object Reference) 테스트의 오탐을 줄이도록 설계된 CLI 도구입니다.

## 책임 고지

- 이 도구 사용에 대한 모든 책임은 사용자에게 있습니다.
- 반드시 명시적으로 승인된 범위의 시스템에서만 테스트하세요.
- 도구 사용으로 발생한 오남용, 손해, 법적 문제에 대해 작성자/유지보수자는 책임지지 않습니다.

## 왜 이런 구조인가

단순 상태코드 체크 대신, API 응답 신호와 브라우저 레벨 검증을 함께 반영하는 증거 체인 기반 점수화를 사용합니다.

## 핵심 기능

- OpenAPI(JSON)에서 IDOR 후보 엔드포인트 자동 추출
  - Path/Query/Body의 id-like 필드 탐지
  - `$ref` 기반 스키마 해석 지원
- 2계정 교차 검증
  - `attacker-own`
  - `attacker-mutated(victim id)`
  - `victim-control`
- 우회 변형 세트
  - Path 우회: trailing slash, double slash, version downgrade, endpoint sibling
  - ID 페이로드: multi-id comma/dot, leading-zero, quoted numeric, encoded space, null-byte
  - 요청 우회: method swap, `X-Original-URL`, `X-Forwarded-For`
- 오탐 억제 점수화
  - 상태코드, 본문 유사도, owner 필드, 응답 안정성 반영
  - 로그인 HTML/인증 리다이렉트/권한거부 문구 감점
- 안전한 리포트 출력
  - `Authorization`, `Cookie`, `X-Api-Key`, JWT/secret/password 자동 마스킹
- Playwright 기반 브라우저 재검증
  - 저장된 storage state(쿠키/세션)로 실제 로그인 상태에서 재검증
- 리포트 출력
  - `output/idor-report.json`
  - `output/idor-report.md`

## 배포 상태

- 현재 npm에는 퍼블리시하지 않았습니다.
- GitHub 소스를 클론해서 로컬 빌드 방식으로 사용합니다.

## 설치 (소스 기준)

```bash
git clone https://github.com/<your-org-or-user>/idors-scout.git
cd idors-scout
npm install
npx playwright install chromium
npm run build
```

## 로컬 CLI 사용

```bash
node dist/cli.js --help
```

## 빠른 시작

1. 예시 설정 복사

OpenAPI 모드:

```bash
cp examples/config.example.json config.json
```

Targets 전용 모드(OpenAPI 없이):

```bash
cp examples/config.targets.example.json config.json
```

2. `config.json` 값 수정

- `baseUrl`
- `openApiSpec`(OpenAPI 모드) 또는 `targets`(Targets 전용 모드)
- `auth.attacker.headers.Authorization` / `auth.victim.headers.Authorization`
- `identifiers` (최소 1개 attacker/victim ID 쌍)

`config.example.json`은 필수 항목만 담은 최소 설정입니다.
대부분의 scan/playwright/output 값은 코드 기본값이 자동 적용됩니다.
세부 튜닝이 필요하면 `examples/config.advanced.example.json`을 사용하세요.

3. 실행

```bash
node dist/cli.js scan -c config.json
```

개발 모드(사전 빌드 없이) 실행:

```bash
npm run dev -- scan -c config.json
```

CLI 옵션:
- `--verbose`: 추가 실행 정보를 출력합니다.
- `--json`: 표준 출력으로 기계 처리 가능한 요약 JSON을 출력합니다.
- `--no-color`: ANSI 컬러 출력을 비활성화합니다.

종료코드:
- `0`: 고신뢰 취약점 없음
- `1`: 실행/설정 오류
- `2`: 하나 이상 취약점 탐지

## Playwright 재검증 활성화

`config.json`에서:

- `playwright.enabled: true`
- `playwright.attackerStorageState`
- `playwright.victimStorageState`

각 계정 로그인 후 `storageState` 파일을 준비합니다(예시):

```ts
import { chromium } from "playwright";

const browser = await chromium.launch({ headless: false });
const context = await browser.newContext();
const page = await context.newPage();
await page.goto("https://app.target.local/login");
// 수동/자동 로그인 완료 후
await context.storageState({ path: "attacker.storage.json" });
await browser.close();
```

victim 계정도 별도 파일로 동일하게 준비하세요.

## OpenAPI 지원 범위

- 입력: JSON 파일 경로 또는 URL
- 대상 메서드: `GET/POST/PUT/PATCH/DELETE` (safe mode에서는 기본 `GET`)
- 후보 조건:
  - `{userId}`, `{projectId}` 같은 path param
  - `?userId=...` 같은 query param
  - body 내 `ownerId`, `userId` 같은 key

## Targets 전용 모드 (OpenAPI 없이)

- `openApiSpec` 대신 `targets`를 설정하면 됩니다.
- 최소 예시:

```json
{
  "baseUrl": "https://api.target.local",
  "targets": [{ "method": "GET", "path": "/users/{uid}" }],
  "auth": {
    "attacker": { "headers": { "Authorization": "Bearer ATTACKER_TOKEN" } },
    "victim": { "headers": { "Authorization": "Bearer VICTIM_TOKEN" } }
  },
  "identifiers": { "uid": { "attacker": "10001", "victim": "20001" } }
}
```

- 각 target의 경로에 있는 `{...}` 값은 `pathParams`로 자동 인식됩니다.

## 생략 시 기본값

- `scan.safeMode: true`
- `scan.concurrency: 4`
- `scan.maxMutationVariants: 12`
- `scan.maxCandidates: 300`
- `scan.timeoutMs: 10000`
- `playwright.enabled: false`
- `outputDir: ./output` (config 파일 기준 상대경로)

## 오탐 감소 전략

- `attacker-mutated`가 `401/403/404`면 강한 음수 가중치
- mutated 응답이 `victim-control`과 유사하고 `attacker-own`과 다를 때 양수 가중치
- owner 관련 필드에서 victim 식별자 확인 시 가중치 증가
- generic/빈 응답은 감점
- Playwright 재검증 불일치 시 confidence 하향
- body mutation은 pivot/owner/identifier 매핑 중심으로 제한

## 파일 구조

- `src/cli.ts`: CLI 진입점
- `src/config.ts`: 설정 로드/검증
- `src/openapi.ts`: OpenAPI 후보 추출
- `src/idor-engine.ts`: API 레벨 IDOR 검증 엔진
- `src/browser-validator.ts`: Playwright 재검증
- `src/report.ts`: JSON/Markdown 리포트

## 테스트

```bash
npm test
```

## 유지보수자 릴리스 체크 (선택)

```bash
npm run publish:check
```

GitHub Actions:
- `.github/workflows/ci.yml` (Node 22/24 build+test)
- `.github/workflows/publish-check.yml` (유지보수자용 publish dry-run)

## 프로젝트 문서

- 기여 가이드: `CONTRIBUTING.md` / `CONTRIBUTING.ko.md`
- 보안 정책: `SECURITY.md` / `SECURITY.ko.md`

## 주의사항

- 허가된 범위에서만 테스트하세요.
- `safeMode: true` 사용을 권장합니다(기본값).
- `scan.maxMutationVariants`로 변형 시도 수를 제한할 수 있습니다(기본 12).
- `scan.concurrency`로 동시 요청 수를 조절할 수 있습니다(기본 4).
- 실환경 테스트에는 rate-limit과 전용 테스트 계정을 준비하세요.
