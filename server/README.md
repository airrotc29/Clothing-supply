# 백엔드 배포 가이드 (Cloudflare Worker)

이 폴더의 `worker.js`는 브라우저와 GitHub 저장소 사이를 중개하는 서버리스 함수입니다.
GitHub에 쓰기 권한이 있는 토큰은 이 Worker 안에만 보관되고, 브라우저(정적 사이트)에는
전달되지 않습니다. **이 배포 작업은 Claude가 대신 해줄 수 없습니다** — Cloudflare 계정과
GitHub 토큰 발급은 본인 계정으로 직접 진행해야 합니다.

## 1) GitHub Fine-grained 토큰 발급

1. GitHub → Settings → Developer settings → Personal access tokens → **Fine-grained tokens** → Generate new token
2. Repository access: **Only select repositories** → `Clothing-supply` 하나만 선택
3. Permissions → Repository permissions → **Contents: Read and write** 만 부여 (다른 권한은 전부 No access)
4. 토큰을 생성하고 값을 복사해 둡니다 (이후 단계에서만 사용, 어디에도 붙여넣지 마세요)

## 2) Cloudflare Workers 배포

```bash
npm install -g wrangler
cd server
wrangler login                      # 브라우저로 Cloudflare 계정 인증
wrangler secret put GITHUB_TOKEN    # 1번에서 발급한 토큰 붙여넣기
wrangler secret put SESSION_SECRET  # 임의의 긴 문자열 (예: openssl rand -hex 32 결과)
wrangler deploy
```

배포가 끝나면 `https://clothing-supply-api.<your-subdomain>.workers.dev` 같은
URL이 출력됩니다. 이 URL을 복사해 두세요.

`wrangler.toml`의 `GITHUB_OWNER` / `GITHUB_REPO` / `DATA_BRANCH` / `ALLOWED_ORIGIN` 값이
본인 환경과 다르면 배포 전에 수정하세요.

## 3) 클라이언트에 Worker 주소 연결

`index.html` 스크립트 상단에 있는

```js
var API_BASE = 'https://REPLACE_WITH_YOUR_WORKER_URL.workers.dev';
```

를 2번에서 받은 실제 Worker URL로 바꿔서 커밋·푸시하세요.

## 4) GitHub Pages 활성화

저장소 Settings → Pages 에서 소스를 이 브랜치(`main`)의 루트(`/`)로 지정하면
`https://airrotc29.github.io/Clothing-supply/` 주소로 접속할 수 있습니다.

## 5) 최초 관리자(본사) 계정 생성 (최초 1회만)

배포 직후, `data/users.json`이 아직 저장소에 없는 상태에서 아래 API를 **딱 한 번** 호출하면
첫 본사 관리자 계정이 만들어집니다. 이후에는 이 API가 항상 거부됩니다.

```bash
curl -X POST https://YOUR_WORKER_URL/api/bootstrap-admin \
  -H "Content-Type: application/json" \
  -d '{"id":"admin","password":"원하는-관리자-비밀번호"}'
```

이후 사이트에서 이 아이디/비밀번호로 로그인하면 관리자 화면에서 사업소별 계정을
직접 발급할 수 있습니다.

## 참고: 왜 서버리스 함수가 필요한가

정적 사이트(GitHub Pages)만으로는 "쓰기 가능한 비밀 토큰"을 안전하게 보관할 방법이 없습니다.
브라우저에 토큰을 넣으면 개발자 도구로 누구나 추출해 저장소에 쓸 수 있게 됩니다. 이 Worker는
그 토큰을 안전하게 보관하고, 브라우저에는 로그인/신청/결재 같은 제한된 기능만 API로 열어줍니다.
