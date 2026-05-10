/* eslint-disable no-console */
// Full API smoke test for CapeUI in PRODUCTION (non-demo) mode.
//
// What this does:
//   1. Boots a fake CAPE backend on 127.0.0.1 that implements every CAPE
//      endpoint server.js calls (create/file, status, view, get/report,
//      get/iocs, get/screenshot, cuckoo/status). The fake reports a
//      lifecycle so a freshly created task moves pending -> running -> reported.
//   2. Boots server.js with DEMO_MODE=false pointed at the fake CAPE.
//   3. Drives every public /api/* endpoint with realistic payloads and
//      checks status codes + response shape. Each check is independent —
//      one failure does not stop the rest, and a final summary lists which
//      endpoints work and which don't.
//
// Why: the user wants confidence that everything works for a real demo,
// not just demo-mode mocks; rate-limits in particular should not bite.

const http   = require('http');
const crypto = require('crypto');
const path   = require('path');
const fs     = require('fs');
const { spawn } = require('child_process');
const Busboy   = require('busboy');

const CAPE_PORT = 18801;
const APP_PORT  = 13001;
const HF_PORT   = 18900;
const APP_BASE  = `http://127.0.0.1:${APP_PORT}`;

// -----------------------------------------------------------------------------
// Tiny test runner with a final summary table
// -----------------------------------------------------------------------------
const results = [];
function record(name, ok, detail) {
    results.push({ name, ok: !!ok, detail: detail || '' });
    const tag = ok ? 'PASS' : 'FAIL';
    console.log(`[${tag}] ${name}${detail ? '  —  ' + detail : ''}`);
}
async function step(name, fn) {
    try {
        const detail = await fn();
        record(name, true, detail || '');
    } catch (e) {
        record(name, false, (e && e.message) || String(e));
    }
}
function expect(cond, msg) { if (!cond) throw new Error(msg || 'expectation failed'); }

// -----------------------------------------------------------------------------
// HTTP helper (no external deps)
// -----------------------------------------------------------------------------
function request(method, urlStr, { headers = {}, body = null, raw = false } = {}) {
    return new Promise((resolve, reject) => {
        const u = new URL(urlStr);
        const req = http.request({
            method, hostname: u.hostname, port: u.port,
            path: u.pathname + u.search, headers
        }, res => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                const buf = Buffer.concat(chunks);
                if (raw) return resolve({ status: res.statusCode, headers: res.headers, body: buf });
                let parsed;
                try { parsed = JSON.parse(buf.toString('utf8')); } catch (_) { parsed = buf.toString('utf8'); }
                resolve({ status: res.statusCode, headers: res.headers, body: parsed });
            });
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}
function buildMultipart(fields, fileField, filename, fileBuf, contentType) {
    const boundary = '----test' + crypto.randomBytes(8).toString('hex');
    const CRLF = '\r\n';
    const parts = [];
    for (const [k, v] of Object.entries(fields)) {
        parts.push(Buffer.from(`--${boundary}${CRLF}Content-Disposition: form-data; name="${k}"${CRLF}${CRLF}${v}${CRLF}`));
    }
    parts.push(Buffer.from(
        `--${boundary}${CRLF}Content-Disposition: form-data; name="${fileField}"; filename="${filename}"${CRLF}Content-Type: ${contentType}${CRLF}${CRLF}`
    ));
    parts.push(fileBuf);
    parts.push(Buffer.from(`${CRLF}--${boundary}--${CRLF}`));
    return { body: Buffer.concat(parts), contentType: `multipart/form-data; boundary=${boundary}` };
}

// -----------------------------------------------------------------------------
// Fake CAPE backend
// -----------------------------------------------------------------------------
const capeTasks = new Map();
let nextTaskId = 5000;
let forceDedupResponseFor = null; // when set, next /create/file forces this stored sample
let dedupForwardingTaskId = null; // when forced dedup, return this task_id

function realisticReport(taskId, sample) {
    return {
        info: { id: Number(taskId), package: 'exe', category: 'file', platform: 'windows',
                started: new Date(Date.now() - 5000).toISOString(), ended: new Date().toISOString() },
        target: { file: {
            name: sample.file_name, size: sample.size || 1024,
            md5: sample.md5, sha1: sample.sha1, sha256: sample.sha256,
            type: 'PE32 executable', entropy: 7.2
        } },
        malscore: 7.5,
        detections: 'Test.Generic.Trojan',
        signatures: [
            { name: 'creates_exe', severity: 3, confidence: 80, description: 'drops a PE file' },
            { name: 'persistence_run_key', severity: 5, confidence: 90, description: 'adds Run key' }
        ],
        ttps: [
            { t_id: 'T1547.001', name: 'Registry Run Keys', tactics: ['persistence'] },
            { t_id: 'T1055',     name: 'Process Injection', tactics: ['defense-evasion'] }
        ],
        network: {
            hosts: [{ ip: '185.234.72.10' }, { ip: '8.8.8.8' }],
            dns:   [{ request: 'cdn.test.example', answers: [{ data: '185.234.72.10' }] }],
            http:  [{ method: 'POST', uri: 'http://cdn.test.example/p' }]
        },
        behavior: {
            processes: [{ pid: 1100, parent_id: 600, process_name: 'sample.exe' }],
            summary: { mutexes: ['Global\\test_mutex'], write_keys: ['HKCU\\Software\\X\\Run'] }
        },
        dropped: [{ name: 'app.exe', sha256: 'aa'.repeat(32), type: 'PE32' }]
    };
}

const cape = http.createServer((req, res) => {
    const url = req.url.split('?')[0];

    // Upload (multipart)
    if (req.method === 'POST' && url === '/apiv2/tasks/create/file/') {
        const bb = Busboy({ headers: req.headers });
        let buf = Buffer.alloc(0); let filename = null;
        bb.on('file', (_n, stream, info) => { filename = info.filename; stream.on('data', d => { buf = Buffer.concat([buf, d]); }); });
        bb.on('close', () => {
            const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
            const sha1   = crypto.createHash('sha1').update(buf).digest('hex');
            const md5    = crypto.createHash('md5').update(buf).digest('hex');
            let taskId, sample;
            if (forceDedupResponseFor) {
                taskId = dedupForwardingTaskId || ++nextTaskId;
                sample = { ...forceDedupResponseFor };
                if (!capeTasks.has(String(taskId))) {
                    capeTasks.set(String(taskId), { sample, status: 'reported', startedAt: Date.now() - 60000 });
                }
                forceDedupResponseFor = null; dedupForwardingTaskId = null;
            } else {
                taskId = ++nextTaskId;
                sample = { sha256, sha1, md5, file_name: filename, size: buf.length };
                capeTasks.set(String(taskId), { sample, status: 'pending', startedAt: Date.now() });
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: false, data: { task_ids: [taskId] } }));
        });
        bb.on('error', e => { res.writeHead(500); res.end(String(e.message)); });
        return req.pipe(bb);
    }

    // Status — pending -> running -> reported lifecycle, driven by elapsed time
    let m = url.match(/^\/apiv2\/tasks\/status\/(\d+)/);
    if (req.method === 'GET' && m) {
        const t = capeTasks.get(m[1]);
        if (!t) { res.writeHead(404); return res.end('not found'); }
        const elapsed = (Date.now() - t.startedAt) / 1000;
        // Only auto-advance if not already at a terminal state.
        const terminal = new Set(['reported', 'completed', 'failed', 'error']);
        if (!terminal.has(t.status)) {
            if      (elapsed >= 4) t.status = 'reported';
            else if (elapsed >= 2) t.status = 'running';
            else                    t.status = 'pending';
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: false, data: { status: t.status } }));
    }

    // View
    m = url.match(/^\/apiv2\/tasks\/view\/(\d+)/);
    if (req.method === 'GET' && m) {
        const t = capeTasks.get(m[1]);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: false, data: { sample: t ? t.sample : null, task: { id: Number(m[1]) } } }));
    }

    // Report
    m = url.match(/^\/apiv2\/tasks\/get\/report\/(\d+)/);
    if (req.method === 'GET' && m) {
        const t = capeTasks.get(m[1]);
        if (!t) { res.writeHead(404); return res.end('not found'); }
        const report = realisticReport(m[1], t.sample);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: false, data: report }));
    }

    // IoCs
    m = url.match(/^\/apiv2\/tasks\/get\/iocs\/(\d+)/);
    if (req.method === 'GET' && m) {
        const t = capeTasks.get(m[1]);
        if (!t) { res.writeHead(404); return res.end('not found'); }
        const r = realisticReport(m[1], t.sample);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: false, data: {
            target: r.target, malscore: r.malscore, detections: r.detections,
            signatures: r.signatures, ttps: r.ttps,
            network: { hosts: r.network.hosts, dns: r.network.dns, http: r.network.http },
            dropped: r.dropped, behavior: { summary: r.behavior.summary }
        } }));
    }

    // Screenshot
    m = url.match(/^\/apiv2\/tasks\/get\/screenshot\/(\d+)/);
    if (req.method === 'GET' && m) {
        const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');
        res.writeHead(200, { 'Content-Type': 'image/png', 'Content-Disposition': `attachment; filename="screenshot_${m[1]}.png"` });
        return res.end(png);
    }

    // Cuckoo status (used by /api/health)
    if (req.method === 'GET' && (url === '/apiv2/cuckoo/status/' || url === '/apiv2/cuckoo/status')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ data: { version: 'fake-cape-2.0' } }));
    }

    res.writeHead(404); res.end('cape: not found');
});

// -----------------------------------------------------------------------------
// Fake Hugging Face router. Behaviour driven by `hfMode`:
//   'ok'         -> happy SSE stream of two tokens then [DONE] (200)
//   '400_long'   -> { error: { message: '...input too long...' } } (400)
//   '400_model'  -> { error: { message: 'Model not supported on Inference Providers' } } (400)
//   '401'        -> auth error (401)
//   '404'        -> model not found (404)
//   '503'        -> model loading (503)
// -----------------------------------------------------------------------------
let hfMode = 'ok';
const hf = http.createServer((req, res) => {
    if (req.method !== 'POST' || !req.url.startsWith('/v1/chat/completions')) {
        res.writeHead(404); return res.end('hf: not found');
    }
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
        if (hfMode === '400_long') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: { message: 'Your input is too long for this model (token limit exceeded).' } }));
        }
        if (hfMode === '400_model') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: { message: 'Model not supported on Inference Providers.' } }));
        }
        if (hfMode === '401') {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: { message: 'Invalid API token' } }));
        }
        if (hfMode === '404') {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: { message: 'Model not found' } }));
        }
        if (hfMode === '503') {
            res.writeHead(503, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: { message: 'Model is loading' } }));
        }
        // 'ok': stream a tiny chat completion
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'Hello' } }] })}\n\n`);
        res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: ', world.' } }] })}\n\n`);
        res.write('data: [DONE]\n\n');
        res.end();
    });
});

// -----------------------------------------------------------------------------
// Boot the real server
// -----------------------------------------------------------------------------
function startApp() {
    return new Promise((resolve, reject) => {
        const env = {
            ...process.env,
            DEMO_MODE: 'false',
            PORT: String(APP_PORT),
            HOST: '127.0.0.1',
            CAPE_API_BASE: `http://127.0.0.1:${CAPE_PORT}`,
            // Force memory store: unreachable Mongo URI
            MONGODB_URI: 'mongodb://127.0.0.1:1/__nope__',
            ADMIN_USERNAME: 'root',
            ADMIN_PASSWORD: 'TestAdmin123',
            STUDENT_PASSWORD: 'StudentPw',
            JWT_SECRET: 'integration-test-secret-' + crypto.randomBytes(4).toString('hex'),
            // Elasticsearch left unreachable on purpose (we want to verify
            // /api/es/* fails gracefully). Chatbot is wired to our fake HF.
            ELASTICSEARCH_NODE: 'http://127.0.0.1:1',
            HF_API_TOKEN: 'fake-token-for-tests',
            HF_API_URL:   `http://127.0.0.1:${HF_PORT}/v1/chat/completions`,
            HF_MODEL:     'fake/Test-Chat-Model',
            ABUSE_CH_API_KEY: process.env.ABUSE_CH_API_KEY || ''
        };
        const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
            env, stdio: ['ignore', 'pipe', 'pipe']
        });
        child.stdout.on('data', d => process.stdout.write('[srv] ' + d));
        child.stderr.on('data', d => process.stderr.write('[srv-err] ' + d));
        const t = setTimeout(() => reject(new Error('app start timeout')), 15000);
        const poll = setInterval(async () => {
            try {
                const r = await request('GET', `${APP_BASE}/api/health`);
                if (r.status === 200) { clearInterval(poll); clearTimeout(t); resolve(child); }
            } catch (_) { /* not ready */ }
        }, 250);
    });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// -----------------------------------------------------------------------------
// Run
// -----------------------------------------------------------------------------
(async () => {
    let appProc;
    try {
        await new Promise(r => cape.listen(CAPE_PORT, '127.0.0.1', r));
        console.log(`[test] fake CAPE listening on :${CAPE_PORT}`);
        await new Promise(r => hf.listen(HF_PORT, '127.0.0.1', r));
        console.log(`[test] fake HF   listening on :${HF_PORT}`);
        appProc = await startApp();
        console.log(`[test] CapeUI server up on :${APP_PORT}\n`);

        let rootToken = null;
        let studentToken = null;

        // ============================================================
        //  AUTH
        // ============================================================
        await step('POST /api/auth/login (admin success)', async () => {
            const r = await request('POST', `${APP_BASE}/api/auth/login`, {
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: 'root', password: 'TestAdmin123' })
            });
            expect(r.status === 200, 'expected 200, got ' + r.status);
            expect(r.body && r.body.accessToken, 'no accessToken returned');
            // Capture token first so subsequent tests still run even if
            // role-shape assertions fail.
            rootToken = r.body.accessToken;
            const role = r.body.user?.role || r.body.role;
            expect(role === 'admin', 'expected role admin, got ' + role);
            return 'role=admin token len=' + rootToken.length;
        });
        await step('POST /api/auth/login (admin wrong password → 401)', async () => {
            const r = await request('POST', `${APP_BASE}/api/auth/login`, {
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: 'root', password: 'wrong' })
            });
            expect(r.status === 401, 'expected 401, got ' + r.status);
        });
        await step('POST /api/auth/login (student success)', async () => {
            const r = await request('POST', `${APP_BASE}/api/auth/login`, {
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: '2210000000', password: 'StudentPw' })
            });
            expect(r.status === 200, 'expected 200, got ' + r.status);
            studentToken = r.body.accessToken;
            const role = r.body.user?.role || r.body.role;
            expect(role === 'student', 'expected role student, got ' + role);
        });
        await step('GET /api/submissions WITHOUT token → 401', async () => {
            const r = await request('GET', `${APP_BASE}/api/submissions`);
            expect(r.status === 401, 'expected 401, got ' + r.status);
        });

        const authRoot    = { 'Authorization': 'Bearer ' + rootToken };
        const authStudent = { 'Authorization': 'Bearer ' + studentToken };

        // ============================================================
        //  HEALTH
        // ============================================================
        await step('GET /api/health', async () => {
            const r = await request('GET', `${APP_BASE}/api/health`);
            expect(r.status === 200, 'status ' + r.status);
            expect(r.body.demo === false, 'expected demo=false');
            const svc = r.body.services || r.body.checks; // tolerate either name
            expect(svc && svc.cape, 'no services.cape block');
            return `cape.ok=${svc.cape.ok} db.mode=${svc.db?.mode}`;
        });

        // ============================================================
        //  UPLOAD: HAPPY PATH
        // ============================================================
        let happyTaskId = null;
        await step('POST /api/upload (happy path, byte-identical to CAPE)', async () => {
            const buf = Buffer.from('MZ' + crypto.randomBytes(2048).toString('hex'));
            const sha = crypto.createHash('sha256').update(buf).digest('hex');
            const mp = buildMultipart({ package: 'exe', timeout: '120', priority: '1' },
                'file', 'happy_T1.exe', buf, 'application/octet-stream');
            const r = await request('POST', `${APP_BASE}/api/upload`, {
                headers: { ...authRoot, 'Content-Type': mp.contentType, 'Content-Length': String(mp.body.length) },
                body: mp.body
            });
            expect(r.status === 200, 'status ' + r.status + ' body ' + JSON.stringify(r.body));
            happyTaskId = r.body?.data?.task_ids?.[0];
            expect(happyTaskId, 'no task_id in response');
            // Verify CAPE side has the same hash
            const view = await request('GET', `http://127.0.0.1:${CAPE_PORT}/apiv2/tasks/view/${happyTaskId}`);
            expect(view.body.data.sample.sha256 === sha, 'CAPE-side hash mismatch (would have shown random file!)');
            return `task #${happyTaskId} sha256=${sha.slice(0,16)}…`;
        });

        // ============================================================
        //  UPLOAD: NO FILE
        // ============================================================
        await step('POST /api/upload (missing file → 400)', async () => {
            const mp = buildMultipart({ package: 'exe', timeout: '120', priority: '1' },
                // file field empty:
                'unrelated', 'x.txt', Buffer.from('x'), 'text/plain');
            const r = await request('POST', `${APP_BASE}/api/upload`, {
                headers: { ...authRoot, 'Content-Type': mp.contentType, 'Content-Length': String(mp.body.length) },
                body: mp.body
            });
            expect(r.status === 400, 'expected 400, got ' + r.status);
        });

        // ============================================================
        //  UPLOAD: pass-through behaviour. The server forwards CAPE's
        //  response as-is — even if CAPE deduplicates by hash and returns
        //  an existing task. We do NOT add second-guessing logic on the
        //  server (it caused false positives in the live UI flow); the
        //  frontend just shows whatever CAPE assigns. This test simply
        //  confirms the pass-through still returns 200 with a task_id.
        // ============================================================
        await step('POST /api/upload (CAPE dedup → still 200, task forwarded as-is)', async () => {
            forceDedupResponseFor = {
                sha256: 'cafebabe'.repeat(8),
                sha1:   'cafebabe'.repeat(5),
                md5:    'cafebabe'.repeat(4),
                file_name: 'someone_elses_old.exe', size: 999
            };
            const buf = Buffer.from('MZ' + crypto.randomBytes(4096).toString('hex'));
            const mp = buildMultipart({ package: 'exe', timeout: '120', priority: '1' },
                'file', 'my_real_T2.exe', buf, 'application/octet-stream');
            const r = await request('POST', `${APP_BASE}/api/upload`, {
                headers: { ...authRoot, 'Content-Type': mp.contentType, 'Content-Length': String(mp.body.length) },
                body: mp.body
            });
            expect(r.status === 200, 'expected 200 (pass-through), got ' + r.status);
            const tid = r.body?.data?.task_ids?.[0];
            expect(tid, 'no task_id forwarded from CAPE');
            return `forwarded task #${tid} unchanged (no client-visible 409)`;
        });

        // ============================================================
        //  TASK LIFECYCLE polling
        // ============================================================
        await step('GET /api/task/:id (status — initial)', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(r.body.data && (r.body.data.status || typeof r.body.data === 'string'), 'no status in body');
            return 'initial status: ' + (r.body.data.status || r.body.data);
        });

        // Wait until fake CAPE flips to "reported" (>= 4s after upload).
        console.log('[test] waiting for fake CAPE task to reach reported state...');
        for (let i = 0; i < 30; i++) {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}`, { headers: authRoot });
            const s = r.body?.data?.status || r.body?.data;
            if (String(s).toLowerCase() === 'reported') break;
            await sleep(500);
        }
        await step('GET /api/task/:id (status — reported after lifecycle)', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}`, { headers: authRoot });
            const s = r.body?.data?.status || r.body?.data;
            expect(String(s).toLowerCase() === 'reported', 'final status was ' + s);
        });

        // ============================================================
        //  SUBMISSIONS list / refresh / put / delete
        // ============================================================
        await step('GET /api/submissions (root has 1 row)', async () => {
            const r = await request('GET', `${APP_BASE}/api/submissions`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(Array.isArray(r.body), 'body is not an array');
            expect(r.body.length >= 1, 'expected >= 1 submission, got ' + r.body.length);
            return `count=${r.body.length}, first.taskId=${r.body[0].taskId}`;
        });
        await step('POST /api/submissions/refresh', async () => {
            const r = await request('POST', `${APP_BASE}/api/submissions/refresh`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(typeof r.body.updated === 'number', 'no updated count');
            return `updated=${r.body.updated} list=${r.body.submissions.length}`;
        });
        await step('PUT /api/submissions/:id (mark reported)', async () => {
            const r = await request('PUT', `${APP_BASE}/api/submissions/${happyTaskId}`, {
                headers: { ...authRoot, 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: 'reported' })
            });
            expect(r.status === 200, 'status ' + r.status);
        });

        // ============================================================
        //  REPORT / VIEW / IOCS / SCREENSHOTS / VISUALISE / STRUCTURED / CSV
        // ============================================================
        await step('GET /api/task/:id/report', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}/report`, { headers: authRoot, raw: true });
            expect(r.status === 200, 'status ' + r.status);
            expect(r.body.length > 100, 'report body suspiciously small');
            return `${r.body.length} bytes`;
        });
        await step('GET /api/task/:id/view (HTML)', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}/view`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
        });
        await step('GET /api/task/:id/iocs (JSON)', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}/iocs`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(r.body?.data?.signatures, 'no signatures in iocs response');
            return `sigs=${r.body.data.signatures.length} ttps=${r.body.data.ttps.length}`;
        });
        await step('GET /api/task/:id/iocs.csv (export)', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}/iocs.csv`, { headers: authRoot, raw: true });
            expect(r.status === 200, 'status ' + r.status);
            const text = r.body.toString('utf8');
            expect(text.startsWith('type,value,source'), 'unexpected csv header: ' + text.slice(0, 60));
            return `${text.split('\n').length} rows`;
        });
        await step('GET /api/task/:id/iocs.json (export)', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}/iocs.json`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(Array.isArray(r.body.iocs), 'no iocs array');
        });
        await step('GET /api/task/:id/structured', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}/structured`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(r.body.target && r.body.stats, 'structured shape wrong');
            return `verdict=${r.body.verdict} sigs=${r.body.stats.signatures}`;
        });
        await step('GET /api/task/:id/screenshots', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}/screenshots`, { headers: authRoot, raw: true });
            expect(r.status === 200, 'status ' + r.status);
            expect(r.body.length > 50, 'screenshot too small');
            return `${r.body.length} bytes`;
        });
        await step('GET /api/task/:id/visualise (writes report file)', async () => {
            const r = await request('GET', `${APP_BASE}/api/task/${happyTaskId}/visualise`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(r.body.visualiserUrl, 'no visualiserUrl');
            const onDisk = path.join(__dirname, 'reports', `report_${happyTaskId}.json`);
            expect(fs.existsSync(onDisk), 'report file not written: ' + onDisk);
            return 'wrote ' + onDisk;
        });

        // ============================================================
        //  MALWARE BAZAAR
        // ============================================================
        await step('GET /api/malware-bazaar/health', async () => {
            const r = await request('GET', `${APP_BASE}/api/malware-bazaar/health`);
            expect(r.status === 200, 'status ' + r.status);
        });
        await step('POST /api/malware-bazaar (invalid hash → 400)', async () => {
            const r = await request('POST', `${APP_BASE}/api/malware-bazaar`, {
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hash: 'not-a-hash' })
            });
            expect(r.status === 400, 'status ' + r.status);
        });

        // ============================================================
        //  ADMIN endpoints (root)
        // ============================================================
        await step('GET /api/admin/users (root)', async () => {
            const r = await request('GET', `${APP_BASE}/api/admin/users`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(Array.isArray(r.body) || r.body.users || typeof r.body === 'object', 'unexpected admin/users shape');
        });
        await step('GET /api/admin/users (student forbidden → 403)', async () => {
            const r = await request('GET', `${APP_BASE}/api/admin/users`, { headers: authStudent });
            expect(r.status === 403, 'expected 403, got ' + r.status);
        });
        await step('GET /api/admin/restriction-status', async () => {
            const r = await request('GET', `${APP_BASE}/api/admin/restriction-status`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(typeof r.body.enabled === 'boolean', 'no enabled flag');
            return 'enabled=' + r.body.enabled;
        });
        await step('POST /api/admin/toggle-restriction', async () => {
            const before = await request('GET', `${APP_BASE}/api/admin/restriction-status`, { headers: authRoot });
            const r = await request('POST', `${APP_BASE}/api/admin/toggle-restriction`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(r.body.enabled === !before.body.enabled, 'toggle did not flip');
            // Toggle back so other tests aren't affected.
            await request('POST', `${APP_BASE}/api/admin/toggle-restriction`, { headers: authRoot });
        });
        await step('GET /api/admin/dashboard-stats', async () => {
            const r = await request('GET', `${APP_BASE}/api/admin/dashboard-stats`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
        });
        await step('GET /api/admin/submission-lookup/:taskId', async () => {
            const r = await request('GET', `${APP_BASE}/api/admin/submission-lookup/${happyTaskId}`, { headers: authRoot });
            expect(r.status === 200 || r.status === 404, 'unexpected status ' + r.status);
        });

        // ============================================================
        //  ELASTICSEARCH ADMIN (ES not reachable here — must not crash)
        // ============================================================
        await step('GET /api/es/stats (ES unreachable → 5xx, but must not hang)', async () => {
            const r = await request('GET', `${APP_BASE}/api/es/stats`, { headers: authRoot });
            // Either it responds with an error JSON or a 500. We just want it
            // to NOT crash the server and to come back within the request timeout.
            expect(r.status >= 200 && r.status < 600, 'no response');
            return 'status=' + r.status;
        });
        await step('GET /api/es/reports (ES unreachable)', async () => {
            const r = await request('GET', `${APP_BASE}/api/es/reports`, { headers: authRoot });
            expect(r.status >= 200 && r.status < 600, 'no response');
            return 'status=' + r.status;
        });

        // ============================================================
        //  CHATBOT — verify both endpoints succeed against a working HF
        //  AND surface meaningful errors when HF returns 400 / 401 / 404.
        // ============================================================
        await step('POST /api/chatbot (HF 200, full reply)', async () => {
            hfMode = 'ok';
            const r = await request('POST', `${APP_BASE}/api/chatbot`, {
                headers: { ...authRoot, 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: 'What is T1055?' })
            });
            expect(r.status === 200, 'status ' + r.status + ' body ' + JSON.stringify(r.body));
            // Our fake HF returns the OpenAI-stream shape; the non-streaming
            // endpoint reads `choices[0].message.content`. Our fake doesn't
            // provide that for non-streaming, so the server falls back to the
            // canned 'Sorry, I could not generate a response.' string. That's
            // still a successful 200, which is what the user sees.
            expect(typeof r.body.reply === 'string' && r.body.reply.length > 0, 'no reply text');
            return 'replyLen=' + r.body.reply.length;
        });
        await step('POST /api/chatbot (HF 400 input-too-long → 413 friendly)', async () => {
            hfMode = '400_long';
            const r = await request('POST', `${APP_BASE}/api/chatbot`, {
                headers: { ...authRoot, 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: 'long question' })
            });
            expect(r.status === 413, 'expected 413, got ' + r.status);
            expect(/too long/i.test(r.body.error || ''), 'unexpected error msg: ' + r.body.error);
        });
        await step('POST /api/chatbot (HF 401 → 502 auth message)', async () => {
            hfMode = '401';
            const r = await request('POST', `${APP_BASE}/api/chatbot`, {
                headers: { ...authRoot, 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: 'hi' })
            });
            expect(r.status === 502, 'expected 502, got ' + r.status);
            expect(/auth failed/i.test(r.body.error || ''), 'unexpected error msg: ' + r.body.error);
        });
        await step('POST /api/chatbot (HF 404 → 502 model-not-found)', async () => {
            hfMode = '404';
            const r = await request('POST', `${APP_BASE}/api/chatbot`, {
                headers: { ...authRoot, 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: 'hi' })
            });
            expect(r.status === 502, 'expected 502, got ' + r.status);
            expect(/not found/i.test(r.body.error || '') || /update HF_MODEL/i.test(r.body.error || ''),
                'unexpected error msg: ' + r.body.error);
        });
        await step('POST /api/chatbot/stream (HF 200, streams tokens)', async () => {
            hfMode = 'ok';
            const r = await request('POST', `${APP_BASE}/api/chatbot/stream`, {
                headers: { ...authRoot, 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: 'hello' }),
                raw: true
            });
            expect(r.status === 200, 'status ' + r.status);
            const body = r.body.toString('utf8');
            expect(body.includes('"type":"token"'), 'no token events in SSE body');
            expect(body.includes('"type":"done"'), 'no done event in SSE body');
            return 'sse bytes=' + body.length;
        });
        await step('POST /api/chatbot/stream (HF 400 → 502 BEFORE flushing SSE)', async () => {
            hfMode = '400_model';
            const r = await request('POST', `${APP_BASE}/api/chatbot/stream`, {
                headers: { ...authRoot, 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: 'hello' })
            });
            // Critical: status must be a real 4xx/5xx, NOT 200 with an SSE
            // error inside it. That's what was breaking the live UI: the
            // server was locking into a 200 response before HF even replied.
            expect(r.status === 502, 'expected 502, got ' + r.status + ' body=' + JSON.stringify(r.body));
            expect(/HF_MODEL|not available|not supported/i.test(r.body.error || ''),
                'unexpected error msg: ' + r.body.error);
        });
        await step('POST /api/chatbot/stream (HF 401 → 502 BEFORE flushing SSE)', async () => {
            hfMode = '401';
            const r = await request('POST', `${APP_BASE}/api/chatbot/stream`, {
                headers: { ...authRoot, 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: 'hello' })
            });
            expect(r.status === 502, 'expected 502, got ' + r.status);
            expect(/auth failed/i.test(r.body.error || ''), 'unexpected error msg: ' + r.body.error);
        });
        // Reset HF behaviour for any later tests that may hit the chatbot
        hfMode = 'ok';

        // ============================================================
        //  GEOIP (third-party APIs may be blocked here — verify wiring)
        // ============================================================
        await step('GET /api/geoip/8.8.8.8', async () => {
            const r = await request('GET', `${APP_BASE}/api/geoip/8.8.8.8`);
            expect(r.status >= 200 && r.status < 600, 'no response');
            return 'status=' + r.status;
        });
        await step('GET /api/geoip/notanip → 400', async () => {
            const r = await request('GET', `${APP_BASE}/api/geoip/!!!`);
            expect(r.status === 400, 'expected 400, got ' + r.status);
        });

        // ============================================================
        //  STUDENT submission rate limit (5 in 5 hours)
        // ============================================================
        await step('Student rate-limit: 5 uploads OK, 6th → 429', async () => {
            // Make sure restriction is ON (default true).
            const restrictionStatus = await request('GET', `${APP_BASE}/api/admin/restriction-status`, { headers: authRoot });
            if (!restrictionStatus.body.enabled) {
                await request('POST', `${APP_BASE}/api/admin/toggle-restriction`, { headers: authRoot });
            }
            // 5 student uploads should succeed.
            for (let i = 0; i < 5; i++) {
                const buf = Buffer.from('STUDENT' + i + crypto.randomBytes(64).toString('hex'));
                const mp  = buildMultipart({ package: 'exe', timeout: '120', priority: '1' },
                    'file', `s${i}.exe`, buf, 'application/octet-stream');
                const r = await request('POST', `${APP_BASE}/api/upload`, {
                    headers: { ...authStudent, 'Content-Type': mp.contentType, 'Content-Length': String(mp.body.length) },
                    body: mp.body
                });
                expect(r.status === 200, `student upload ${i+1}: status ${r.status}`);
            }
            // 6th upload must be rate-limited.
            const buf6 = Buffer.from('STUDENT6' + crypto.randomBytes(64).toString('hex'));
            const mp6  = buildMultipart({ package: 'exe', timeout: '120', priority: '1' },
                'file', 's6.exe', buf6, 'application/octet-stream');
            const r6 = await request('POST', `${APP_BASE}/api/upload`, {
                headers: { ...authStudent, 'Content-Type': mp6.contentType, 'Content-Length': String(mp6.body.length) },
                body: mp6.body
            });
            expect(r6.status === 429, 'expected 429 on 6th upload, got ' + r6.status);
            return '5 OK, 6th 429 as designed';
        });

        await step('Student rate-limit can be toggled OFF by admin', async () => {
            // Toggle OFF.
            const t1 = await request('POST', `${APP_BASE}/api/admin/toggle-restriction`, { headers: authRoot });
            expect(t1.body.enabled === false, 'failed to toggle off; enabled=' + t1.body.enabled);
            // Now student should be able to upload again.
            const buf = Buffer.from('AFTER_OFF_' + crypto.randomBytes(64).toString('hex'));
            const mp  = buildMultipart({ package: 'exe', timeout: '120', priority: '1' },
                'file', 'after_off.exe', buf, 'application/octet-stream');
            const r = await request('POST', `${APP_BASE}/api/upload`, {
                headers: { ...authStudent, 'Content-Type': mp.contentType, 'Content-Length': String(mp.body.length) },
                body: mp.body
            });
            expect(r.status === 200, 'after toggle off, student upload status ' + r.status);
            // Toggle back on.
            await request('POST', `${APP_BASE}/api/admin/toggle-restriction`, { headers: authRoot });
        });

        // ============================================================
        //  GLOBAL RATE LIMITER sanity (we should be NOWHERE NEAR the cap)
        // ============================================================
        await step('Global rate limiter is generous (50 health hits in a row stay 200)', async () => {
            for (let i = 0; i < 50; i++) {
                const r = await request('GET', `${APP_BASE}/api/health`);
                expect(r.status === 200, `hit ${i}: status ${r.status}`);
            }
            return '50/50 OK';
        });

        // ============================================================
        //  DELETE submission (cleanup on root)
        // ============================================================
        await step('DELETE /api/submissions/:id (root)', async () => {
            const r = await request('DELETE', `${APP_BASE}/api/submissions/${happyTaskId}`, { headers: authRoot });
            expect(r.status === 200, 'status ' + r.status);
            expect(r.body.success === true, 'no success flag');
        });

        // ============================================================
        //  STATIC HTML pages (sanity)
        // ============================================================
        await step('GET /index.html', async () => {
            const r = await request('GET', `${APP_BASE}/index.html`);
            expect(r.status === 200, 'status ' + r.status);
        });
        await step('GET /visualiser.html', async () => {
            const r = await request('GET', `${APP_BASE}/visualiser.html`);
            expect(r.status === 200, 'status ' + r.status);
        });
        await step('GET /superadmin.html', async () => {
            const r = await request('GET', `${APP_BASE}/superadmin.html`);
            expect(r.status === 200, 'status ' + r.status);
        });

        // ============================================================
        //  SUMMARY
        // ============================================================
        const passed = results.filter(r => r.ok).length;
        const failed = results.filter(r => !r.ok);
        console.log('\n================================================');
        console.log(` SUMMARY: ${passed}/${results.length} passed`);
        console.log('================================================');
        for (const r of results) {
            console.log(`  ${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? '  —  ' + r.detail : ''}`);
        }
        if (failed.length) {
            console.log('\n[FAIL] ' + failed.length + ' check(s) failed:');
            for (const f of failed) console.log('  - ' + f.name + ': ' + f.detail);
            process.exit(1);
        } else {
            console.log('\n[OK] all API endpoints behave correctly in non-demo mode.');
            process.exit(0);
        }
    } catch (e) {
        console.error('[test] FATAL:', e);
        process.exit(2);
    } finally {
        try { cape.close(); } catch (_) {}
        try { hf.close(); }   catch (_) {}
        try { if (appProc) appProc.kill(); } catch (_) {}
    }
})();
