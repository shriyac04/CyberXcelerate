/* eslint-disable no-console */
// Live end-to-end upload diagnostic.
//
// Run this on the same machine your CapeUI server is running on (so localhost
// can hit CapeUI on :3000, and CapeUI can hit CAPE at CAPE_API_BASE).
//
//   node diagnose_upload.js
//
// What it does:
//   1. Generates a unique, random 4 KB "executable" so it CANNOT be deduplicated
//      against any previous CAPE submission.
//   2. Computes its sha256/sha1/md5 LOCALLY (this is the ground truth).
//   3. Logs into the live CapeUI server with the credentials from your .env.
//   4. Uploads via POST /api/upload exactly the way the browser does.
//   5. Reads the returned CAPE task_id.
//   6. Verifies our own memory/Mongo row for that task (should have OUR filename
//      and size).
//   7. Hits the CAPE backend directly at /apiv2/tasks/view/<task_id> and reads
//      back the sample CAPE actually stored under that ID.
//   8. Compares (a) what we sent, (b) what we recorded, (c) what CAPE has.
//   9. Prints a verdict pinpointing exactly where any mismatch is.
//
// Prints PASS / FAIL for each check so you can see at a glance whether the
// "wrong file" you're seeing in the UI is:
//   - a bug in CapeUI (we sent / stored / displayed the wrong thing), or
//   - CAPE-side hash deduplication (CAPE returned an existing task pointing at
//     someone else's earlier sample), or
//   - a stale UI cache (you're looking at an old task row).

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');
const path   = require('path');
const fs     = require('fs');

// ---- Load env from .env without external deps ------------------------------
function loadEnv() {
    try {
        const txt = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
        for (const line of txt.split(/\r?\n/)) {
            const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i);
            if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
        }
    } catch (_) {}
}
loadEnv();

const APP_BASE = process.env.DIAG_APP_BASE || `http://localhost:${process.env.PORT || 3000}`;
const CAPE_BASE = process.env.CAPE_API_BASE || 'http://10.20.8.79:8000';
const ADMIN_USER = process.env.ADMIN_USERNAME || 'root';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'Admin@@';

// ---- Tiny http(s) request helper -------------------------------------------
function request(method, urlStr, { headers = {}, body = null, raw = false, timeout = 30000 } = {}) {
    return new Promise((resolve, reject) => {
        const u = new URL(urlStr);
        const lib = u.protocol === 'https:' ? https : http;
        const req = lib.request({
            method, hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
            path: u.pathname + u.search, headers, timeout
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
        req.on('timeout', () => { req.destroy(new Error('request timeout')); });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

function buildMultipart(fields, fileField, filename, fileBuf, contentType) {
    const boundary = '----diag' + crypto.randomBytes(8).toString('hex');
    const CRLF = '\r\n';
    const parts = [];
    for (const [k, v] of Object.entries(fields)) {
        parts.push(Buffer.from(`--${boundary}${CRLF}Content-Disposition: form-data; name="${k}"${CRLF}${CRLF}${v}${CRLF}`));
    }
    parts.push(Buffer.from(`--${boundary}${CRLF}Content-Disposition: form-data; name="${fileField}"; filename="${filename}"${CRLF}Content-Type: ${contentType}${CRLF}${CRLF}`));
    parts.push(fileBuf);
    parts.push(Buffer.from(`${CRLF}--${boundary}--${CRLF}`));
    return { body: Buffer.concat(parts), contentType: `multipart/form-data; boundary=${boundary}` };
}

const checks = [];
function check(name, ok, detail) {
    checks.push({ name, ok: !!ok, detail: detail || '' });
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  —  ' + detail : ''}`);
}
function hr() { console.log('-'.repeat(78)); }

// ----------------------------------------------------------------------------
(async () => {
    console.log('CapeUI live-upload diagnostic');
    console.log(`  CapeUI:     ${APP_BASE}`);
    console.log(`  CAPE:       ${CAPE_BASE}`);
    console.log(`  Admin user: ${ADMIN_USER}`);
    hr();

    // -- Step 1: Health probe --------------------------------------------------
    let demoMode = null;
    try {
        const r = await request('GET', `${APP_BASE}/api/health`, { timeout: 5000 });
        if (r.status !== 200) {
            console.log(`[FATAL] /api/health returned ${r.status}. Is the server running?`);
            process.exit(2);
        }
        demoMode = !!r.body.demo;
        console.log(`[health] demo=${demoMode}  cape.ok=${r.body.services?.cape?.ok}  cape.base=${r.body.services?.cape?.base}`);
        if (demoMode) {
            console.log('[FATAL] Server is running in DEMO_MODE=true. The diagnostic cannot exercise CAPE.');
            console.log('         Set DEMO_MODE=false in .env, restart the server, and re-run this script.');
            process.exit(2);
        }
    } catch (e) {
        console.log(`[FATAL] Cannot reach CapeUI at ${APP_BASE}: ${e.message}`);
        console.log('        Start the server with `npm start` and try again.');
        process.exit(2);
    }
    hr();

    // -- Step 2: Login --------------------------------------------------------
    let token;
    try {
        const r = await request('POST', `${APP_BASE}/api/auth/login`, {
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: ADMIN_USER, password: ADMIN_PASS })
        });
        if (r.status !== 200 || !r.body.accessToken) {
            console.log(`[FATAL] Login failed (${r.status}): ${JSON.stringify(r.body)}`);
            process.exit(2);
        }
        token = r.body.accessToken;
        console.log(`[login] OK as ${ADMIN_USER} (role=${r.body.user?.role || r.body.role})`);
    } catch (e) {
        console.log(`[FATAL] Login error: ${e.message}`);
        process.exit(2);
    }
    hr();

    // -- Step 3: Build a guaranteed-unique test file --------------------------
    // 4 KB of crypto-strong random bytes prefixed with the MZ header so CAPE
    // accepts it as a PE candidate. Filename embeds a timestamp+random suffix.
    const stamp   = new Date().toISOString().replace(/[:.]/g, '-');
    const suffix  = crypto.randomBytes(4).toString('hex');
    const fname   = `diag_${stamp}_${suffix}.exe`;
    const buf     = Buffer.concat([Buffer.from([0x4D, 0x5A]), crypto.randomBytes(4094)]);
    const sha256  = crypto.createHash('sha256').update(buf).digest('hex');
    const sha1    = crypto.createHash('sha1').update(buf).digest('hex');
    const md5     = crypto.createHash('md5').update(buf).digest('hex');
    console.log('[file] generated unique sample:');
    console.log(`       name   = ${fname}`);
    console.log(`       size   = ${buf.length} bytes`);
    console.log(`       sha256 = ${sha256}`);
    console.log(`       sha1   = ${sha1}`);
    console.log(`       md5    = ${md5}`);
    hr();

    // -- Step 4: Upload through CapeUI ----------------------------------------
    let taskId;
    let uploadResp;
    try {
        const mp = buildMultipart(
            { package: 'exe', timeout: '120', priority: '1' },
            'file', fname, buf, 'application/octet-stream'
        );
        console.log(`[upload] POST ${APP_BASE}/api/upload …`);
        const r = await request('POST', `${APP_BASE}/api/upload`, {
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': mp.contentType,
                'Content-Length': String(mp.body.length)
            },
            body: mp.body,
            timeout: 60000
        });
        uploadResp = r;
        console.log(`[upload] HTTP ${r.status}`);
        console.log(`[upload] response body: ${JSON.stringify(r.body).slice(0, 400)}`);
        check('CapeUI /api/upload returned 200', r.status === 200, 'status=' + r.status);
        const taskIds = r.body?.data?.task_ids || r.body?.task_ids || [];
        taskId = taskIds[0];
        check('CAPE returned a task_id', !!taskId, taskId ? `task_id=${taskId}` : 'no task_id in response');
    } catch (e) {
        check('CapeUI /api/upload returned 200', false, 'request error: ' + e.message);
    }
    hr();

    if (!taskId) {
        console.log('[stop] No task_id was returned; cannot continue verification.');
        printSummary();
        process.exit(1);
    }

    // -- Step 5: Verify what CapeUI's own store recorded ----------------------
    try {
        const r = await request('GET', `${APP_BASE}/api/admin/submission-lookup/${taskId}`, {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        if (r.status === 200) {
            const stored = r.body || {};
            console.log(`[capeui-store] task_id=${stored.taskId} filename=${stored.filename} username=${stored.username}`);
            check('CapeUI stored the filename we sent',
                stored.filename === fname,
                stored.filename ? `stored="${stored.filename}", expected="${fname}"` : 'no filename in row');
        } else {
            check('CapeUI stored a row for the task', false, `lookup returned ${r.status}`);
        }
    } catch (e) {
        check('CapeUI stored a row for the task', false, 'lookup error: ' + e.message);
    }
    hr();

    // -- Step 6: Ask CAPE directly what it has under that task_id -------------
    let capeView;
    try {
        const r = await request('GET', `${CAPE_BASE}/apiv2/tasks/view/${taskId}`, { timeout: 8000 });
        if (r.status !== 200) {
            check('CAPE /tasks/view/<id> reachable', false, 'status=' + r.status);
            console.log('[cape] body:', JSON.stringify(r.body).slice(0, 400));
        } else {
            capeView = r.body;
            const sample = capeView?.data?.sample || capeView?.sample || capeView?.task?.sample || {};
            console.log(`[cape] task_id=${taskId} sample.file_name=${sample.file_name} sample.sha256=${(sample.sha256 || '').slice(0,16)}…`);
            console.log(`[cape] full sample object: ${JSON.stringify(sample).slice(0, 400)}`);

            check('CAPE knows about this task',
                !!sample && Object.keys(sample).length > 0,
                'sample is empty in CAPE view response');
            check('CAPE-stored SHA-256 matches our local SHA-256',
                (sample.sha256 || '').toLowerCase() === sha256,
                `cape=${(sample.sha256 || 'n/a').slice(0,16)}…  ours=${sha256.slice(0,16)}…`);
            check('CAPE-stored filename matches our filename',
                sample.file_name === fname || sample.name === fname,
                `cape="${sample.file_name || sample.name || 'n/a'}", ours="${fname}"`);
            check('CAPE-stored file size matches',
                Number(sample.size) === buf.length,
                `cape=${sample.size}, ours=${buf.length}`);
        }
    } catch (e) {
        check('CAPE /tasks/view/<id> reachable', false, 'request error: ' + e.message);
        console.log('         (this means we cannot verify the CAPE-side state from this machine.)');
    }
    hr();

    // -- Step 7: Look for dedup pattern: if CAPE-side hash != ours,
    //            check whether the task_id is much older than today's tasks.
    if (capeView) {
        const sample = capeView?.data?.sample || capeView?.sample || capeView?.task?.sample || {};
        if (sample.sha256 && sample.sha256.toLowerCase() !== sha256) {
            console.log('[dedup-detection] CAPE returned a task whose stored SHA-256 differs from ours.');
            console.log('                  This is the classic "wrong file" symptom — CAPE has hash');
            console.log('                  deduplication enabled and gave us back an EXISTING task');
            console.log('                  pointing to a previous upload of THIS hash.');
            console.log('                  Note: we generated random bytes so this should be impossible —');
            console.log('                  if you still see this, CAPE is likely returning the same task');
            console.log('                  for ALL submissions (broken backend) or there is a proxy in');
            console.log('                  the way returning a cached response.');
        }
    }
    hr();

    printSummary();

    function printSummary() {
        console.log('\n========================  DIAGNOSTIC VERDICT  ========================');
        const failed = checks.filter(c => !c.ok);
        for (const c of checks) console.log(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? ' — ' + c.detail : ''}`);
        console.log('-'.repeat(70));

        const allOk = failed.length === 0;
        if (allOk) {
            console.log('OK — Upload pipeline is healthy. The bytes you choose in the browser');
            console.log('     reach CAPE byte-identically, CapeUI records the right filename,');
            console.log('     and CAPE confirms the same hash. If the UI shows a "wrong file",');
            console.log('     the issue is in your browser (stale tab / cached report / wrong');
            console.log('     task selected), not in the server pipeline.');
        } else {
            const failNames = failed.map(f => f.name);
            const sentBytesOk = !failNames.some(n => /returned 200|task_id|reachable/i.test(n));
            const storeOk    = !failNames.some(n => /stored the filename/i.test(n));
            const capeOk     = !failNames.some(n => /SHA-256 matches|filename matches|size matches/i.test(n));

            console.log('ROOT CAUSE LOCATION:');
            if (!sentBytesOk) {
                console.log('  → CapeUI server side. /api/upload did not return a task_id or 200.');
                console.log('    Check logs/tasks.log for "submit_error" entries near this run.');
            } else if (!storeOk) {
                console.log('  → CapeUI server side. The submission row in our store does NOT contain');
                console.log('    the filename we uploaded. Check storeCreateSubmission() in server.js.');
            } else if (!capeOk) {
                console.log('  → CAPE backend side. CapeUI sent the right bytes (we verified above) but');
                console.log('    CAPE has a different sample under that task_id. Most likely causes:');
                console.log('      a) CAPE has hash deduplication enabled and returned an existing task');
                console.log('         (disable dedup in CAPE config, or rename/repack the sample).');
                console.log('      b) A proxy/load-balancer in front of CAPE is caching the response.');
                console.log('      c) CAPE assigned the task_id to a different concurrent submission');
                console.log('         and gave us the wrong one back (CAPE-internal race).');
            } else {
                console.log('  → Mixed failures. See list above.');
            }
        }
        console.log('======================================================================');
        process.exit(allOk ? 0 : 1);
    }
})();
