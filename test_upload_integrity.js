/* eslint-disable no-console */
// Integration test: verifies that /api/upload (in non-demo mode) actually
// uploads the user's bytes AND detects when CAPE returns a deduplicated
// task whose stored sample doesn't match.
//
// We can't reach the real CAPE (10.20.8.79:8000) from this machine, so we
// stand up a fake CAPE on 127.0.0.1 that lets us script the response of
// /apiv2/tasks/view/<id>. The CapeUI server is started with CAPE_API_BASE
// pointing at the fake. Real /api/upload code path runs unmodified.

const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const Busboy = require('busboy');

const CAPE_PORT = 18800;
const APP_PORT  = 13000;
const APP_BASE  = `http://127.0.0.1:${APP_PORT}`;

function log(...a) { console.log('[test]', ...a); }
function fail(msg) { console.error('[test] FAIL:', msg); process.exit(1); }
function ok(msg)   { console.log('[test] PASS:', msg); }

// -----------------------------------------------------------------------------
// Fake CAPE
// -----------------------------------------------------------------------------
// Behaviour:
//   POST /apiv2/tasks/create/file/   -> echo file's real sha256 (ASSIGNED) and
//                                       remember it for `view`. Optional
//                                       env-controlled override forces a
//                                       DIFFERENT stored sha256 to simulate
//                                       CAPE returning a deduped older task.
//   GET  /apiv2/tasks/view/:id       -> { data: { sample: { sha256, file_name } } }
const capeStateByTask = new Map();
let nextTaskId = 1000;
let forceDedupResponse = null; // { sha256, file_name } or null
let lastUploadObserved = null; // { sha256, size, name }

const cape = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url.startsWith('/apiv2/tasks/create/file/')) {
        const bb = Busboy({ headers: req.headers });
        let buf = Buffer.alloc(0);
        let filename = null;
        bb.on('file', (_name, stream, info) => {
            filename = info.filename;
            stream.on('data', d => { buf = Buffer.concat([buf, d]); });
        });
        bb.on('close', () => {
            const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
            lastUploadObserved = { sha256, size: buf.length, name: filename };
            const taskId = nextTaskId++;
            // If forceDedupResponse is set, the stored sample for this task
            // will look like an unrelated previous submission.
            const stored = forceDedupResponse
                ? { ...forceDedupResponse }
                : { sha256, file_name: filename };
            capeStateByTask.set(String(taskId), stored);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: false, data: { task_ids: [taskId] } }));
        });
        bb.on('error', e => {
            res.writeHead(500); res.end(String(e.message));
        });
        req.pipe(bb);
        return;
    }
    const m = req.url.match(/^\/apiv2\/tasks\/view\/(\d+)/);
    if (req.method === 'GET' && m) {
        const stored = capeStateByTask.get(m[1]) || null;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: false, data: { sample: stored } }));
        return;
    }
    if (req.method === 'GET' && req.url.startsWith('/apiv2/cuckoo/status/')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: { version: 'fake-cape-1.0' } }));
        return;
    }
    res.writeHead(404); res.end('not found');
});

// -----------------------------------------------------------------------------
// HTTP helpers (no extra deps; multipart by hand)
// -----------------------------------------------------------------------------
function httpJson(method, urlStr, { headers = {}, body = null } = {}) {
    return new Promise((resolve, reject) => {
        const u = new URL(urlStr);
        const req = http.request({
            method,
            hostname: u.hostname,
            port: u.port,
            path: u.pathname + u.search,
            headers
        }, res => {
            let chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                const raw = Buffer.concat(chunks);
                let parsed = null;
                try { parsed = JSON.parse(raw.toString('utf8')); } catch (_) { parsed = raw.toString('utf8'); }
                resolve({ status: res.statusCode, body: parsed, raw });
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
        parts.push(Buffer.from(
            `--${boundary}${CRLF}` +
            `Content-Disposition: form-data; name="${k}"${CRLF}${CRLF}` +
            `${v}${CRLF}`
        ));
    }
    parts.push(Buffer.from(
        `--${boundary}${CRLF}` +
        `Content-Disposition: form-data; name="${fileField}"; filename="${filename}"${CRLF}` +
        `Content-Type: ${contentType}${CRLF}${CRLF}`
    ));
    parts.push(fileBuf);
    parts.push(Buffer.from(`${CRLF}--${boundary}--${CRLF}`));
    return { body: Buffer.concat(parts), contentType: `multipart/form-data; boundary=${boundary}` };
}

// -----------------------------------------------------------------------------
// Boot CapeUI server (server.js) with our fake CAPE
// -----------------------------------------------------------------------------
function startApp() {
    return new Promise((resolve, reject) => {
        const env = {
            ...process.env,
            DEMO_MODE: 'false',
            PORT: String(APP_PORT),
            HOST: '127.0.0.1',
            CAPE_API_BASE: `http://127.0.0.1:${CAPE_PORT}`,
            // Skip Mongo: invalid URI guarantees no connection so memory store kicks in.
            MONGODB_URI: 'mongodb://127.0.0.1:1/__nope__',
            ADMIN_USERNAME: 'root',
            ADMIN_PASSWORD: 'TestAdmin123',
            STUDENT_PASSWORD: 'StudentPw',
            JWT_SECRET: 'integration-test-secret'
        };
        const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
            env,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        let out = '';
        child.stdout.on('data', d => { out += d; process.stdout.write('[srv] ' + d); });
        child.stderr.on('data', d => { process.stderr.write('[srv-err] ' + d); });
        const t = setTimeout(() => reject(new Error('app start timeout')), 12000);
        const poll = setInterval(async () => {
            try {
                const r = await httpJson('GET', `${APP_BASE}/api/health`);
                if (r.status === 200) { clearInterval(poll); clearTimeout(t); resolve(child); }
            } catch (_) { /* not ready */ }
        }, 250);
    });
}

// -----------------------------------------------------------------------------
// Run
// -----------------------------------------------------------------------------
(async () => {
    let appProc;
    try {
        await new Promise(r => cape.listen(CAPE_PORT, '127.0.0.1', r));
        log(`fake CAPE listening on :${CAPE_PORT}`);
        appProc = await startApp();
        log(`CapeUI server up on :${APP_PORT} with CAPE_API_BASE=http://127.0.0.1:${CAPE_PORT}`);

        // Login as root.
        const login = await httpJson('POST', `${APP_BASE}/api/auth/login`, {
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: 'root', password: 'TestAdmin123' })
        });
        if (login.status !== 200 || !login.body?.accessToken) {
            fail('login failed: ' + JSON.stringify(login.body));
        }
        const token = login.body.accessToken;
        ok('login (root) → got JWT');

        // ---- Test 1: HAPPY PATH — CAPE keeps our bytes; server should accept.
        forceDedupResponse = null;
        const fileBuf1 = Buffer.from('MZ' + crypto.randomBytes(2048).toString('hex'));
        const localSha1 = crypto.createHash('sha256').update(fileBuf1).digest('hex');
        const mp1 = buildMultipart(
            { package: 'exe', timeout: '120', priority: '1' },
            'file', 'fresh_sample_T1.exe', fileBuf1, 'application/octet-stream'
        );
        const r1 = await httpJson('POST', `${APP_BASE}/api/upload`, {
            headers: {
                'Content-Type': mp1.contentType,
                'Content-Length': String(mp1.body.length),
                'Authorization': 'Bearer ' + token
            },
            body: mp1.body
        });
        log('happy-path response status:', r1.status, 'body:', JSON.stringify(r1.body));
        if (r1.status !== 200) fail('happy path: expected 200, got ' + r1.status);
        const taskIdHappy = r1.body?.data?.task_ids?.[0];
        if (!taskIdHappy) fail('happy path: no task_id in response');
        if (lastUploadObserved.sha256 !== localSha1) {
            fail('happy path: CAPE saw different bytes than we sent! ' +
                 `local=${localSha1} cape=${lastUploadObserved.sha256}`);
        }
        ok(`happy path: CAPE received the EXACT bytes we sent (sha256=${localSha1.slice(0,16)}…), task #${taskIdHappy}`);

        // ---- Test 2: DEDUP — CAPE returns task pointing to a different sample.
        // This is the bug the user described: "a random file is shown".
        forceDedupResponse = {
            sha256: 'deadbeef'.repeat(8), // 64 hex chars, definitely not ours
            file_name: 'someone_elses_old_sample.exe'
        };
        const fileBuf2 = Buffer.from('MZ' + crypto.randomBytes(4096).toString('hex'));
        const localSha2 = crypto.createHash('sha256').update(fileBuf2).digest('hex');
        const mp2 = buildMultipart(
            { package: 'exe', timeout: '120', priority: '1' },
            'file', 'my_real_file_T2.exe', fileBuf2, 'application/octet-stream'
        );
        const r2 = await httpJson('POST', `${APP_BASE}/api/upload`, {
            headers: {
                'Content-Type': mp2.contentType,
                'Content-Length': String(mp2.body.length),
                'Authorization': 'Bearer ' + token
            },
            body: mp2.body
        });
        log('dedup response status:', r2.status, 'body:', JSON.stringify(r2.body));
        if (r2.status !== 409) fail('dedup: expected 409, got ' + r2.status);
        const det = r2.body?.details;
        if (!det || !det.yourFile || !det.capeStored) fail('dedup: missing details in 409 response');
        if (det.yourFile.sha256 !== localSha2) fail('dedup: yourFile.sha256 wrong');
        if (det.capeStored.sha256 !== forceDedupResponse.sha256) fail('dedup: capeStored.sha256 wrong');
        if (det.capeStored.name !== forceDedupResponse.file_name) fail('dedup: capeStored.name wrong');
        ok('dedup mismatch: server correctly returned 409 with hash-mismatch details');
        log('  → yourFile  :', det.yourFile.name, det.yourFile.sha256.slice(0, 16) + '…');
        log('  → capeStored:', det.capeStored.name, det.capeStored.sha256.slice(0, 16) + '…',
            'task #' + det.capeStored.taskId);

        // ---- Test 3: HAPPY PATH AGAIN after dedup — make sure state is clean
        forceDedupResponse = null;
        const fileBuf3 = Buffer.from('MZ' + crypto.randomBytes(1024).toString('hex'));
        const localSha3 = crypto.createHash('sha256').update(fileBuf3).digest('hex');
        const mp3 = buildMultipart(
            { package: 'exe', timeout: '120', priority: '1' },
            'file', 'fresh_sample_T3.exe', fileBuf3, 'application/octet-stream'
        );
        const r3 = await httpJson('POST', `${APP_BASE}/api/upload`, {
            headers: {
                'Content-Type': mp3.contentType,
                'Content-Length': String(mp3.body.length),
                'Authorization': 'Bearer ' + token
            },
            body: mp3.body
        });
        if (r3.status !== 200) fail('post-dedup happy: expected 200, got ' + r3.status);
        if (lastUploadObserved.sha256 !== localSha3) fail('post-dedup happy: byte mismatch');
        ok(`post-dedup happy: clean upload still works (sha256=${localSha3.slice(0,16)}…), task #${r3.body?.data?.task_ids?.[0]}`);

        // ---- Verify dedup was logged in tasks.log
        const logsPath = path.join(__dirname, 'logs', 'tasks.log');
        if (fs.existsSync(logsPath)) {
            const tail = fs.readFileSync(logsPath, 'utf8').split('\n').slice(-15).join('\n');
            if (tail.includes('submit_dedup_mismatch')) {
                ok('tasks.log received submit_dedup_mismatch event');
            } else {
                log('WARN: tasks.log does not contain submit_dedup_mismatch in the last 15 lines (still ok if log was rotated).');
            }
        }

        console.log('\n[test] ALL CHECKS PASSED');
        process.exit(0);
    } catch (e) {
        console.error('[test] ERROR:', e);
        process.exit(1);
    } finally {
        try { cape.close(); } catch (_) {}
        try { if (appProc) appProc.kill(); } catch (_) {}
    }
})();
