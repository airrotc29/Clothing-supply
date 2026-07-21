/*
 * 피복 신청·승인 관리 시스템 - 백엔드(Cloudflare Worker)
 *
 * 이 파일은 브라우저(정적 사이트)와 GitHub 저장소 사이의 유일한 중개자입니다.
 * GitHub에 쓰기 권한이 있는 토큰은 이 Worker의 환경변수(Secret)에만 저장되고,
 * 브라우저에는 절대 전달되지 않습니다. 브라우저는 이 Worker가 제공하는
 * HTTP API만 호출합니다.
 *
 * 데이터는 이 저장소의 `data/` 폴더 아래 JSON 파일로 저장됩니다.
 *   data/users.json                     - 계정 목록 (아이디, 비밀번호 해시, 역할, 소속 사업소)
 *   data/sites/{siteId}/requests.json   - 사업소별 "피복신청서" 제출 이력 (대기/승인/반려)
 *   data/sites/{siteId}/issues.json     - 승인된 신청에서 자동 생성되는 지급이력(직원·품목·지급일)
 *
 * 필요한 환경변수(Secret/Var)는 server/README.md 를 참고하세요.
 */

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function jsonResponse(env, data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({}, JSON_HEADERS, corsHeaders(env)),
  });
}

function errorResponse(env, message, status) {
  return jsonResponse(env, { error: message }, status || 400);
}

/* ---------- base64url / crypto 유틸 ---------- */

function bytesToBase64Url(bytes) {
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64UrlToBytes(b64url) {
  var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function utf8ToBytes(str) { return new TextEncoder().encode(str); }
function bytesToUtf8(bytes) { return new TextDecoder().decode(bytes); }

async function pbkdf2Hash(password, saltBytes) {
  var keyMaterial = await crypto.subtle.importKey('raw', utf8ToBytes(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  var salt = crypto.getRandomValues(new Uint8Array(16));
  var hash = await pbkdf2Hash(password, salt);
  return bytesToBase64Url(salt) + '.' + bytesToBase64Url(hash);
}

async function verifyPassword(password, stored) {
  var parts = String(stored || '').split('.');
  if (parts.length !== 2) return false;
  var salt = base64UrlToBytes(parts[0]);
  var expected = base64UrlToBytes(parts[1]);
  var actual = await pbkdf2Hash(password, salt);
  if (actual.length !== expected.length) return false;
  var diff = 0;
  for (var i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

async function hmacSign(env, data) {
  var key = await crypto.subtle.importKey('raw', utf8ToBytes(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  var sig = await crypto.subtle.sign('HMAC', key, utf8ToBytes(data));
  return bytesToBase64Url(new Uint8Array(sig));
}

async function signToken(env, payload) {
  var body = bytesToBase64Url(utf8ToBytes(JSON.stringify(payload)));
  var sig = await hmacSign(env, body);
  return body + '.' + sig;
}

async function verifyToken(env, token) {
  if (!token) return null;
  var parts = String(token).split('.');
  if (parts.length !== 2) return null;
  var expectedSig = await hmacSign(env, parts[0]);
  if (expectedSig !== parts[1]) return null;
  var payload;
  try { payload = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[0]))); } catch (e) { return null; }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}

function getBearerToken(request) {
  var h = request.headers.get('Authorization') || '';
  var m = h.match(/^Bearer\s+(.+)$/);
  return m ? m[1] : null;
}

async function requireAuth(env, request) {
  var payload = await verifyToken(env, getBearerToken(request));
  if (!payload) return null;
  return payload;
}

/* ---------- GitHub Contents API ---------- */

function githubApiUrl(env, path) {
  return 'https://api.github.com/repos/' + env.GITHUB_OWNER + '/' + env.GITHUB_REPO + '/contents/' + path;
}

function githubHeaders(env) {
  return {
    'Authorization': 'token ' + env.GITHUB_TOKEN,
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'clothing-supply-worker',
  };
}

// returns { data, sha } or { data: null, sha: null } if file doesn't exist yet
async function readJsonFile(env, path) {
  var res = await fetch(githubApiUrl(env, path) + '?ref=' + (env.DATA_BRANCH || 'main'), { headers: githubHeaders(env) });
  if (res.status === 404) return { data: null, sha: null };
  if (!res.ok) throw new Error('GitHub read failed (' + res.status + '): ' + path);
  var body = await res.json();
  var contentStr;
  if (body.content) {
    contentStr = bytesToUtf8(standardBase64ToBytes(body.content));
  } else {
    // GitHub Contents API leaves `content` empty for files over 1MB — fall back to the raw media type
    var rawRes = await fetch(githubApiUrl(env, path) + '?ref=' + (env.DATA_BRANCH || 'main'), {
      headers: Object.assign({}, githubHeaders(env), { 'Accept': 'application/vnd.github.raw+json' }),
    });
    if (!rawRes.ok) throw new Error('GitHub raw read failed (' + rawRes.status + '): ' + path);
    contentStr = await rawRes.text();
  }
  if (!contentStr) return { data: [], sha: body.sha };
  return { data: JSON.parse(contentStr), sha: body.sha };
}

// GitHub returns standard base64 (with newlines), not base64url — decode accordingly
function standardBase64ToBytes(b64) {
  var clean = b64.replace(/\n/g, '');
  var bin = atob(clean);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function writeRawContent(env, path, contentB64, message, sha) {
  var body = {
    message: message,
    content: contentB64,
    branch: env.DATA_BRANCH || 'main',
  };
  if (sha) body.sha = sha;
  var res = await fetch(githubApiUrl(env, path), {
    method: 'PUT',
    headers: Object.assign({ 'Content-Type': 'application/json' }, githubHeaders(env)),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    var errText = await res.text();
    throw new Error('GitHub write failed (' + res.status + '): ' + path + ' - ' + errText);
  }
  var result = await res.json();
  return result.content.sha;
}

async function writeJsonFile(env, path, dataObj, message, sha) {
  var contentStr = JSON.stringify(dataObj, null, 2);
  var contentB64 = btoa(unescape(encodeURIComponent(contentStr)));
  return await writeRawContent(env, path, contentB64, message, sha);
}

/* ---------- 데이터 헬퍼 ---------- */

async function loadUsers(env) {
  var r = await readJsonFile(env, 'data/users.json');
  return { users: r.data || [], sha: r.sha };
}

async function loadSiteRequests(env, siteId) {
  var r = await readJsonFile(env, 'data/sites/' + siteId + '/requests.json');
  return { requests: r.data || [], sha: r.sha };
}

async function loadSiteIssues(env, siteId) {
  var r = await readJsonFile(env, 'data/sites/' + siteId + '/issues.json');
  return { issues: r.data || [], sha: r.sha };
}

function sanitizeSiteId(name) {
  var base = String(name || '').trim().toLowerCase()
    .replace(/[^a-z0-9가-힣\-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  return (base || 'site') + '-' + Math.random().toString(36).slice(2, 8);
}

function toNumber(v) {
  var n = Number(String(v == null ? '' : v).replace(/,/g, ''));
  return isNaN(n) ? 0 : n;
}

function isStaff(auth) {
  return !!auth && (auth.role === 'admin' || auth.role === 'ceo');
}

function todayIso() {
  var d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

/* ---------- 라우트 핸들러: 인증/계정 ---------- */

async function handleLogin(env, request) {
  var body = await request.json().catch(function () { return {}; });
  var id = String(body.id || '').trim();
  var password = String(body.password || '');
  if (!id || !password) return errorResponse(env, '아이디와 비밀번호를 입력하세요.', 400);

  var { users } = await loadUsers(env);
  var user = users.find(function (u) { return u.id === id; });
  if (!user) return errorResponse(env, '아이디 또는 비밀번호가 올바르지 않습니다.', 401);

  var ok = await verifyPassword(password, user.passwordHash);
  if (!ok) return errorResponse(env, '아이디 또는 비밀번호가 올바르지 않습니다.', 401);

  var token = await signToken(env, {
    uid: user.id, role: user.role, siteId: user.siteId, siteName: user.siteName,
    exp: Date.now() + 1000 * 60 * 60 * 12, // 12시간
  });
  return jsonResponse(env, { token: token, uid: user.id, role: user.role, siteId: user.siteId, siteName: user.siteName });
}

// 최초 1회: users.json 이 저장소에 아직 없을 때만 동작 (첫 관리자 계정 생성)
async function handleBootstrapAdmin(env, request) {
  var { users, sha } = await loadUsers(env);
  if (users.length) return errorResponse(env, '이미 초기화되었습니다. 관리자 계정으로 로그인해 사용자를 추가하세요.', 403);

  var body = await request.json().catch(function () { return {}; });
  var id = String(body.id || '').trim();
  var password = String(body.password || '');
  if (!id || !password) return errorResponse(env, '아이디와 비밀번호를 입력하세요.', 400);

  var passwordHash = await hashPassword(password);
  var adminUser = { id: id, passwordHash: passwordHash, role: 'admin', siteId: null, siteName: null, createdAt: new Date().toISOString() };
  await writeJsonFile(env, 'data/users.json', [adminUser], '최초 관리자 계정 생성: ' + id, sha);
  return jsonResponse(env, { ok: true });
}

async function handleCreateUser(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'admin') return errorResponse(env, '관리자만 사용할 수 있습니다.', 403);

  var body = await request.json().catch(function () { return {}; });
  var accountType = body.accountType === 'ceo' ? 'ceo' : 'user';
  var id = String(body.id || '').trim();
  var password = String(body.password || '');
  if (!id || !password) return errorResponse(env, '아이디와 비밀번호를 입력하세요.', 400);

  var { users, sha } = await loadUsers(env);
  if (users.some(function (u) { return u.id === id; })) return errorResponse(env, '이미 존재하는 아이디입니다.', 409);

  if (accountType === 'ceo') {
    var name = String(body.name || '대표자').trim();
    var passwordHash = await hashPassword(password);
    var ceoUser = { id: id, passwordHash: passwordHash, role: 'ceo', siteId: null, siteName: name, createdAt: new Date().toISOString() };
    users.push(ceoUser);
    await writeJsonFile(env, 'data/users.json', users, '대표자 계정 생성: ' + id, sha);
    return jsonResponse(env, { ok: true });
  }

  var siteName = String(body.siteName || '').trim();
  if (!siteName) return errorResponse(env, '사업소명을 입력하세요.', 400);

  var siteId = sanitizeSiteId(siteName);
  var passwordHash2 = await hashPassword(password);
  var newUser = { id: id, passwordHash: passwordHash2, role: 'user', siteId: siteId, siteName: siteName, createdAt: new Date().toISOString() };
  users.push(newUser);
  await writeJsonFile(env, 'data/users.json', users, '사업소 계정 생성: ' + id + ' (' + siteName + ')', sha);
  await writeJsonFile(env, 'data/sites/' + siteId + '/requests.json', [], '신청 이력 초기화: ' + siteName, null);
  await writeJsonFile(env, 'data/sites/' + siteId + '/issues.json', [], '지급이력 초기화: ' + siteName, null);

  return jsonResponse(env, { ok: true, siteId: siteId });
}

async function handleListUsers(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'admin') return errorResponse(env, '관리자만 사용할 수 있습니다.', 403);

  var { users } = await loadUsers(env);
  var list = users.filter(function (u) { return u.role !== 'admin'; }).map(function (u) {
    return { id: u.id, role: u.role, siteName: u.siteName, siteId: u.siteId, createdAt: u.createdAt };
  });
  return jsonResponse(env, { users: list });
}

/* ---------- 라우트 핸들러: 사업소 피복신청서 ---------- */

function sortRequests(requests) {
  return requests.slice().sort(function (a, b) {
    return (b.submittedAt || '').localeCompare(a.submittedAt || '');
  });
}

async function handleGetRequests(env, request, url) {
  var auth = await requireAuth(env, request);
  if (!auth) return errorResponse(env, '로그인이 필요합니다.', 401);
  var siteId = (auth.role === 'user' ? auth.siteId : url.searchParams.get('siteId'));
  if (!siteId) return errorResponse(env, 'siteId가 필요합니다.', 400);
  var { requests } = await loadSiteRequests(env, siteId);
  return jsonResponse(env, { requests: sortRequests(requests) });
}

async function handleSubmitRequest(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'user') return errorResponse(env, '사업소 계정만 사용할 수 있습니다.', 403);

  var body = await request.json().catch(function () { return {}; });
  var requestDate = String(body.requestDate || '').trim();
  var incomingRows = Array.isArray(body.rows) ? body.rows : [];
  if (!requestDate) return errorResponse(env, '신청일을 입력하세요.', 400);

  var rows = incomingRows.map(function (r) {
    var qty = toNumber(r.qty);
    var unitPrice = toNumber(r.unitPrice);
    return {
      name: String(r.name || '').trim(),
      position: String(r.position || '').trim(),
      item: String(r.item || '').trim(),
      spec: String(r.spec || '').trim(),
      qty: qty,
      unitPrice: unitPrice,
      amount: qty * unitPrice, // 항상 서버에서 재계산
      reason: String(r.reason || '').trim(),
    };
  }).filter(function (r) { return r.name || r.item; });
  if (!rows.length) return errorResponse(env, '신청 품목을 1건 이상 입력하세요.', 400);

  var totalAmount = rows.reduce(function (sum, r) { return sum + r.amount; }, 0);

  var { requests, sha } = await loadSiteRequests(env, auth.siteId);
  var nextId = requests.reduce(function (max, r) { return Math.max(max, r.id || 0); }, 0) + 1;
  var reqObj = {
    id: nextId,
    requestDate: requestDate,
    rows: rows,
    totalAmount: totalAmount,
    siteAddress: String(body.siteAddress || ''),
    contact: String(body.contact || ''),
    status: 'pending',
    submittedAt: new Date().toISOString(),
    submittedBy: auth.uid,
    adminReviewedAt: null,
    adminReviewedBy: null,
    adminNote: '',
    ceoReviewedAt: null,
    ceoReviewedBy: null,
    ceoNote: '',
  };
  requests.push(reqObj);
  await writeJsonFile(env, 'data/sites/' + auth.siteId + '/requests.json', requests, '피복신청서 제출: ' + auth.siteId + ' (' + requestDate + ')', sha);
  return jsonResponse(env, { ok: true, request: reqObj });
}

/* ---------- 라우트 핸들러: 본사 결재 ---------- */

async function handleAdminAllRequests(env, request, url) {
  var auth = await requireAuth(env, request);
  if (!auth || !isStaff(auth)) return errorResponse(env, '본사 또는 대표자 계정만 사용할 수 있습니다.', 403);
  var statusFilter = url.searchParams.get('status'); // pending | submitted_to_ceo | approved | rejected | (없으면 전체)
  var siteFilter = url.searchParams.get('siteId'); // 특정 사업소만 (없으면 전체 사업소)

  var { users } = await loadUsers(env);
  var sites = users.filter(function (u) { return u.role === 'user' && (!siteFilter || u.siteId === siteFilter); });

  var all = [];
  for (var i = 0; i < sites.length; i++) {
    var u = sites[i];
    var reqs = [];
    try {
      var r = await loadSiteRequests(env, u.siteId);
      reqs = r.requests;
    } catch (e) { /* ignore, treat as no requests */ }
    reqs.forEach(function (rq) {
      all.push(Object.assign({}, rq, { siteId: u.siteId, siteName: u.siteName }));
    });
  }
  if (statusFilter) all = all.filter(function (r) { return r.status === statusFilter; });
  all.sort(function (a, b) { return (b.submittedAt || '').localeCompare(a.submittedAt || ''); });

  return jsonResponse(env, { requests: all });
}

// 결재 흐름: 사업소 제출(pending) -> 본사 1차 검토(admin) -> 대표자 최종 결재(ceo) -> approved/rejected
// 본사는 pending 건을 '대표자에게 상신'(submit_to_ceo) 하거나 '반려'(rejected) 할 수 있고,
// 상신한 건은 대표자가 아직 처리하기 전이라면 '회수'(recall) 하여 pending으로 되돌릴 수 있다.
async function handleReviewRequest(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || !isStaff(auth)) return errorResponse(env, '본사 또는 대표자 계정만 사용할 수 있습니다.', 403);

  var body = await request.json().catch(function () { return {}; });
  var siteId = String(body.siteId || '').trim();
  var requestId = Number(body.requestId);
  var decision = String(body.decision || '');
  var note = String(body.note || '').trim();
  if (!siteId || !requestId) return errorResponse(env, 'siteId와 requestId가 필요합니다.', 400);

  var { requests, sha } = await loadSiteRequests(env, siteId);
  var target = requests.find(function (r) { return r.id === requestId; });
  if (!target) return errorResponse(env, '신청서를 찾을 수 없습니다.', 404);

  var commitMessage;
  var shouldCreateIssues = false;

  if (auth.role === 'admin') {
    if (decision === 'recall') {
      if (target.status !== 'submitted_to_ceo') return errorResponse(env, '대표자에게 상신 중인 신청서만 회수할 수 있습니다.', 409);
      if (target.ceoReviewedAt) return errorResponse(env, '이미 대표자가 처리한 신청서는 회수할 수 없습니다.', 409);
      if (target.adminReviewedBy !== auth.uid) return errorResponse(env, '본인이 상신한 신청서만 회수할 수 있습니다.', 403);
      target.status = 'pending';
      target.adminReviewedAt = null;
      target.adminReviewedBy = null;
      target.adminNote = '';
      commitMessage = '피복신청서 상신 회수: ' + siteId + ' #' + requestId;
    } else {
      if (target.status !== 'pending') return errorResponse(env, '본사 검토 대상이 아닙니다.', 409);
      if (decision !== 'submit_to_ceo' && decision !== 'rejected') return errorResponse(env, 'decision은 submit_to_ceo, rejected, recall 중 하나여야 합니다.', 400);
      target.adminReviewedAt = new Date().toISOString();
      target.adminReviewedBy = auth.uid;
      target.adminNote = note;
      target.status = decision === 'submit_to_ceo' ? 'submitted_to_ceo' : 'rejected';
      commitMessage = '피복신청서 ' + (decision === 'submit_to_ceo' ? '대표자 상신' : '본사 반려') + ': ' + siteId + ' #' + requestId;
    }
  } else { // ceo
    if (target.status !== 'submitted_to_ceo') return errorResponse(env, '대표자 결재 대상이 아닙니다.', 409);
    if (decision !== 'approved' && decision !== 'rejected') return errorResponse(env, 'decision은 approved 또는 rejected여야 합니다.', 400);
    target.ceoReviewedAt = new Date().toISOString();
    target.ceoReviewedBy = auth.uid;
    target.ceoNote = note;
    target.status = decision;
    shouldCreateIssues = decision === 'approved';
    commitMessage = '피복신청서 대표자 ' + (decision === 'approved' ? '승인' : '반려') + ': ' + siteId + ' #' + requestId;
  }

  await writeJsonFile(env, 'data/sites/' + siteId + '/requests.json', requests, commitMessage, sha);

  if (shouldCreateIssues) {
    var { issues, sha: issuesSha } = await loadSiteIssues(env, siteId);
    var issueDate = todayIso();
    target.rows.forEach(function (row) {
      issues.push({
        employeeName: row.name,
        position: row.position,
        item: row.item,
        spec: row.spec,
        qty: row.qty,
        issueDate: issueDate,
        requestId: requestId,
      });
    });
    await writeJsonFile(env, 'data/sites/' + siteId + '/issues.json', issues, '지급이력 반영: ' + siteId + ' #' + requestId, issuesSha);
  }

  return jsonResponse(env, { ok: true, request: target });
}

/* ---------- 라우트 핸들러: 지급이력대장 ---------- */

async function handleGetIssues(env, request, url) {
  var auth = await requireAuth(env, request);
  if (!auth) return errorResponse(env, '로그인이 필요합니다.', 401);
  var siteId = (auth.role === 'user' ? auth.siteId : url.searchParams.get('siteId'));
  if (!siteId) return errorResponse(env, 'siteId가 필요합니다.', 400);
  var { issues } = await loadSiteIssues(env, siteId);
  return jsonResponse(env, { issues: issues });
}

/* ---------- 라우트 핸들러: 본사 통계 ---------- */

async function handleAdminStats(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || !isStaff(auth)) return errorResponse(env, '본사 또는 대표자 계정만 사용할 수 있습니다.', 403);

  var { users } = await loadUsers(env);
  var sites = users.filter(function (u) { return u.role === 'user'; });

  var siteStats = [];
  var grand = { pendingCount: 0, submittedToCeoCount: 0, approvedCount: 0, rejectedCount: 0, approvedAmount: 0 };
  for (var i = 0; i < sites.length; i++) {
    var u = sites[i];
    var reqs = [];
    try {
      var r = await loadSiteRequests(env, u.siteId);
      reqs = r.requests;
    } catch (e) { /* ignore, treat as no requests */ }
    var pending = reqs.filter(function (r) { return r.status === 'pending'; });
    var submittedToCeo = reqs.filter(function (r) { return r.status === 'submitted_to_ceo'; });
    var approved = reqs.filter(function (r) { return r.status === 'approved'; });
    var rejected = reqs.filter(function (r) { return r.status === 'rejected'; });
    var approvedAmount = approved.reduce(function (sum, r) { return sum + (r.totalAmount || 0); }, 0);
    var sorted = sortRequests(reqs);

    grand.pendingCount += pending.length;
    grand.submittedToCeoCount += submittedToCeo.length;
    grand.approvedCount += approved.length;
    grand.rejectedCount += rejected.length;
    grand.approvedAmount += approvedAmount;

    siteStats.push({
      siteId: u.siteId, siteName: u.siteName,
      requestCount: reqs.length,
      pendingCount: pending.length,
      submittedToCeoCount: submittedToCeo.length,
      approvedCount: approved.length,
      rejectedCount: rejected.length,
      approvedAmount: approvedAmount,
      lastSubmittedAt: sorted.length ? sorted[0].submittedAt : null,
    });
  }
  siteStats.sort(function (a, b) { return (b.pendingCount + b.submittedToCeoCount) - (a.pendingCount + a.submittedToCeoCount); });

  return jsonResponse(env, {
    siteCount: sites.length,
    grand: grand,
    sites: siteStats,
  });
}

/* ---------- 라우트 핸들러: 월간 보고서 ---------- */

async function handleMonthlyReport(env, request, url) {
  var auth = await requireAuth(env, request);
  if (!auth || !isStaff(auth)) return errorResponse(env, '본사 또는 대표자 계정만 사용할 수 있습니다.', 403);

  var month = String(url.searchParams.get('month') || '').trim(); // 'YYYY-MM'
  if (!/^\d{4}-\d{2}$/.test(month)) return errorResponse(env, 'month는 YYYY-MM 형식이어야 합니다.', 400);

  var { users } = await loadUsers(env);
  var sites = users.filter(function (u) { return u.role === 'user'; });

  var siteRows = [];
  var itemAgg = {};
  var grand = { count: 0, amount: 0 };

  for (var i = 0; i < sites.length; i++) {
    var u = sites[i];
    var reqs = [];
    try {
      var r = await loadSiteRequests(env, u.siteId);
      reqs = r.requests;
    } catch (e) { /* ignore */ }
    var approvedInMonth = reqs.filter(function (rq) {
      return rq.status === 'approved' && rq.ceoReviewedAt && rq.ceoReviewedAt.slice(0, 7) === month;
    });
    var siteAmount = 0;
    approvedInMonth.forEach(function (rq) {
      siteAmount += rq.totalAmount || 0;
      rq.rows.forEach(function (row) {
        var key = row.item || '기타';
        if (!itemAgg[key]) itemAgg[key] = { qty: 0, amount: 0 };
        itemAgg[key].qty += toNumber(row.qty);
        itemAgg[key].amount += toNumber(row.amount);
      });
    });
    grand.count += approvedInMonth.length;
    grand.amount += siteAmount;
    if (approvedInMonth.length) {
      siteRows.push({ siteId: u.siteId, siteName: u.siteName, count: approvedInMonth.length, amount: siteAmount });
    }
  }
  siteRows.sort(function (a, b) { return b.amount - a.amount; });
  var itemRows = Object.keys(itemAgg).map(function (k) { return { item: k, qty: itemAgg[k].qty, amount: itemAgg[k].amount }; });
  itemRows.sort(function (a, b) { return b.amount - a.amount; });

  return jsonResponse(env, { month: month, grand: grand, sites: siteRows, items: itemRows });
}

/* ---------- 진입점 ---------- */

export default {
  async fetch(request, env) {
    var url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(env) });
    }
    try {
      if (url.pathname === '/api/login' && request.method === 'POST') return await handleLogin(env, request);
      if (url.pathname === '/api/bootstrap-admin' && request.method === 'POST') return await handleBootstrapAdmin(env, request);
      if (url.pathname === '/api/admin/users' && request.method === 'GET') return await handleListUsers(env, request);
      if (url.pathname === '/api/admin/users' && request.method === 'POST') return await handleCreateUser(env, request);
      if (url.pathname === '/api/admin/stats' && request.method === 'GET') return await handleAdminStats(env, request);
      if (url.pathname === '/api/admin/monthly-report' && request.method === 'GET') return await handleMonthlyReport(env, request, url);
      if (url.pathname === '/api/admin/requests' && request.method === 'GET') return await handleAdminAllRequests(env, request, url);
      if (url.pathname === '/api/admin/requests/review' && request.method === 'POST') return await handleReviewRequest(env, request);
      if (url.pathname === '/api/admin/ledger' && request.method === 'GET') return await handleGetIssues(env, request, url);
      if (url.pathname === '/api/site/requests' && request.method === 'GET') return await handleGetRequests(env, request, url);
      if (url.pathname === '/api/site/requests' && request.method === 'POST') return await handleSubmitRequest(env, request);
      if (url.pathname === '/api/site/ledger' && request.method === 'GET') return await handleGetIssues(env, request, url);
      return errorResponse(env, 'Not found', 404);
    } catch (err) {
      return errorResponse(env, '서버 오류: ' + (err && err.message ? err.message : String(err)), 500);
    }
  },
};
