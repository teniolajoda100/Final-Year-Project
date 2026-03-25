/**
 * CVision Automated Test Suite
 * Run: node cvision.test.js
 * Requires Node 18+ (built-in fetch, no installs needed)
 */
'use strict';

const BASE  = process.env.CVISION_URL || 'http://localhost:3000';
const EMAIL = `auto_${Date.now()}@test.ie`;
const PASS  = 'TestPass123!';

let passed = 0, failed = 0;
const failures = [];

function assert(label, ok, detail = '') {
    if (ok) { passed++; console.log(`  ✅ ${label}`); }
    else     { failed++; failures.push(`${label}${detail ? ' — ' + detail : ''}`); console.log(`  ❌ ${label}${detail ? ' — ' + detail : ''}`); }
}

function section(name) { console.log(`\n── ${name} ${'─'.repeat(50 - name.length)}`); }

let session = '', recruiterSession = '', candidateId = null, analysisData = null;

async function req(method, path, body, cookie = '') {
    const r = await fetch(`${BASE}${path}`, {
        method, redirect: 'manual',
        headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
        body: body ? JSON.stringify(body) : undefined
    });
    let json = null; try { json = await r.json(); } catch (_) {}
    return { status: r.status, json, headers: r.headers };
}

async function post(path, fd, cookie = '') {
    const r = await fetch(`${BASE}${path}`, {
        method: 'POST', redirect: 'manual',
        headers: cookie ? { Cookie: cookie } : {},
        body: fd
    });
    let json = null; try { json = await r.json(); } catch (_) {}
    return { status: r.status, json, headers: r.headers };
}

function cookie(headers) {
    const m = (headers.get('set-cookie') || '').match(/connect\.sid=[^;]+/);
    return m ? m[0] : '';
}

// URL-encoded form post — matches what Express urlencoded() middleware expects
async function postForm(path, fields, cookie = '') {
    const body = Object.entries(fields)
        .map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    const r = await fetch(`${BASE}${path}`, {
        method: 'POST', redirect: 'manual',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            ...(cookie ? { Cookie: cookie } : {})
        },
        body
    });
    let json = null; try { json = await r.json(); } catch (_) {}
    return { status: r.status, json, headers: r.headers };
}

// Minimal valid PDF containing the CV text — avoids mammoth DOCX parsing
function makePDF(text) {
    const safe = text.replace(/\\/g,'\\').replace(/\(/g,'\\(').replace(/\)/g,'\\)');
    const stream = 'BT /F1 10 Tf 30 800 Td (' + safe + ') Tj ET';
    const len    = stream.length;
    const n = '\n';
    const body =
        '%PDF-1.4'+n+
        '1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj'+n+
        '2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj'+n+
        '3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>>>>>>>endobj'+n+
        '4 0 obj<</Length '+len+'>>'+n+'stream'+n+stream+n+'endstream'+n+'endobj'+n+
        'xref'+n+'0 5'+n+'0000000000 65535 f '+n+
        'trailer<</Size 5/Root 1 0 R>>'+n+'startxref'+n+'9'+n+'%%EOF';
    return Buffer.from(body);
}
const CV = `John Smith — Software Engineer
SKILLS: JavaScript, React, Node.js, PostgreSQL, Python, AWS, Docker
EXPERIENCE: Senior Developer at TechCorp (2021–Present) — designed and built REST APIs, led a team of 4, reduced latency by 40%.
Junior Developer (2019–2021) — built React components, wrote unit tests.
EDUCATION: BSc Computer Science, UCD 2015–2019`;

// ── 1. Auth ───────────────────────────────────────────────────
async function testAuth() {
    section('1. Authentication');

    // Signup — use URL-encoded body (Express urlencoded() middleware)
    const r = await postForm('/signup', { fullName:'Auto Tester', email:EMAIL, password:PASS, role:'student' });
    assert('Student signup (200/302)', [200, 302].includes(r.status), `got ${r.status}`);
    session = cookie(r.headers);
    // If redirect, follow it to pick up the session cookie properly
    if (!session && r.status === 302) {
        const loc = r.headers.get('location') || '/dashboard';
        const follow = await req('GET', loc.startsWith('http') ? loc.replace(BASE,'') : loc, null, '');
        session = cookie(follow.headers) || session;
    }
    assert('Session cookie set', !!session);

    // Session info
    const si = await req('GET', '/session-info', null, session);
    assert('Session loggedIn:true', si.json?.loggedIn === true);

    // Auth guard
    const ag = await req('GET', '/api/latest-cv-analysis');
    assert('Unauthenticated API returns 401', ag.status === 401);

    // Wrong password
    const wr = await postForm('/login', { email:EMAIL, password:'wrongpassword' });
    assert('Wrong password denied', ![302].includes(wr.status) || wr.status === 200);

    // Recruiter account
    const rr = await postForm('/signup', { fullName:'HR Bot', email:`rec_${Date.now()}@test.ie`, password:PASS, role:'recruiter' });
    recruiterSession = cookie(rr.headers);
    assert('Recruiter signup', [200, 302].includes(rr.status), `got ${rr.status}`);
}

// ── 2. CV Upload & Analysis ───────────────────────────────────
async function testCV() {
    section('2. CV Upload & Analysis');

    // Valid upload — send as PDF so server uses extractPDFText() not mammoth
    const fd = new FormData();
    const pdfBytes = makePDF(CV);
    fd.append('cvFile', new Blob([pdfBytes], { type: 'application/pdf' }), 'cv.pdf');
    const t0 = Date.now();
    const r  = await post('/analyze', fd, session);
    const ms = Date.now() - t0;

    assert('CV upload returns 200', r.status === 200);
    assert('No error in response', !r.json?.error, r.json?.error);

    if (r.json && !r.json.error) {
        analysisData = r.json;
        assert('Skills array returned',      Array.isArray(r.json.skills));
        assert('At least 3 skills found',    r.json.skills.length >= 3, `got ${r.json.skills.length}`);
        assert('Summary object present',     !!r.json.summary);
        assert('Analysis under 45s',         ms < 45000, `${ms}ms`);

        const s = r.json.skills[0];
        assert('Skill has name',      typeof s.name       === 'string');
        assert('Skill score 1–10',    s.score >= 1 && s.score <= 10, `score=${s.score}`);
        assert('Skill has bloomLevel',typeof s.bloomLevel  === 'string');
        assert('Skill has category',  typeof s.category   === 'string');

        const BLOOMS = ['remember','understand','apply','analys','evaluate','create'];
        const allValid = r.json.skills.every(sk =>
            BLOOMS.some(b => sk.bloomLevel.toLowerCase().includes(b))
        );
        assert("Bloom's levels are valid", allValid);
    }

    // Invalid file
    const bad = new FormData();
    bad.append('cvFile', new Blob(['x'], { type: 'application/octet-stream' }), 'bad.exe');
    const br = await post('/analyze', bad, session);
    assert('Invalid file type rejected', !!br.json?.error || br.status >= 400);

    // Empty file
    const ef = new FormData();
    ef.append('cvFile', new Blob([''], { type: 'application/pdf' }), 'empty.pdf');
    const er = await post('/analyze', ef, session);
    assert('Empty file rejected', !!er.json?.error || er.status >= 400);
}

// ── 3. Analysis API & Job Comparison ─────────────────────────
async function testJobAPI() {
    section('3. Analysis API & Job Comparison');

    const la = await req('GET', '/api/latest-cv-analysis', null, session);
    assert('Latest analysis returns 200',    la.status === 200);
    assert('hasAnalysis flag present',       typeof la.json?.hasAnalysis === 'boolean');

    const jt = await req('GET', '/api/job-titles');
    assert('Job titles endpoint works',      jt.status === 200);
    assert('At least 5 job titles',          (jt.json?.jobTitles?.length || 0) >= 5);

    const jc = await req('POST', '/api/compare-with-job', { jobTitle: 'Software Engineer' }, session);
    assert('Job comparison returns 200',     jc.status === 200);
    assert('No error in comparison',         !jc.json?.error, jc.json?.error);
    if (!jc.json?.error) {
        assert('matchedSkills array present',    Array.isArray(jc.json?.skillComparison?.matchedSkills));
        assert('Readiness score 0–100',          jc.json?.metrics?.readiness?.score >= 0 && jc.json?.metrics?.readiness?.score <= 100);
        assert('Relevance score 0–100',          jc.json?.metrics?.relevance?.score  >= 0 && jc.json?.metrics?.relevance?.score  <= 100);
    }

    const nc = await req('POST', '/api/compare-with-job', { jobTitle: 'Developer' });
    assert('Unauthenticated comparison is 401', nc.status === 401);
}

// ── 4. Recruiter Pipeline ─────────────────────────────────────
async function testRecruiter() {
    section('4. Recruiter Pipeline');

    if (!recruiterSession) { console.log('  ⏭  Skipped — recruiter session not established'); return; }

    const stats = await req('GET', '/api/recruiter/stats', null, recruiterSession);
    assert('Recruiter stats returns 200',    stats.status === 200);
    assert('Stats has total_candidates',     typeof stats.json?.stats?.total_candidates !== 'undefined');

    const fd = new FormData();
    const recPdf = makePDF(CV);
    fd.append('cvFile', new Blob([recPdf], { type: 'application/pdf' }), 'cand.pdf');
    fd.append('candidateName', 'Test Candidate');
    fd.append('jobTitle', 'Software Engineer');
    const up = await post('/api/recruiter/candidates/upload', fd, recruiterSession);
    assert('Candidate upload returns 200',   up.status === 200);
    assert('Upload success:true',            up.json?.success === true, up.json?.error);

    if (up.json?.success) {
        candidateId = up.json.candidateId;
        assert('candidateId returned',           !!candidateId);
        assert('matchPercentage is 0–100',       up.json.analysis?.matchPercentage >= 0 && up.json.analysis?.matchPercentage <= 100);
    }

    for (const status of ['shortlisted', 'interviewing', 'hired']) {
        if (!candidateId) break;
        const r = await req('PATCH', `/api/recruiter/candidates/${candidateId}/status`, { status }, recruiterSession);
        assert(`Status → '${status}' succeeds`, r.json?.success === true);
    }

    // Student blocked from recruiter routes
    const blocked = await req('GET', '/api/recruiter/candidates', null, session);
    assert('Student blocked from recruiter routes', blocked.status === 401 || blocked.status === 403 || blocked.json?.success === false);
}

// ── 5. Error Handling & Performance ──────────────────────────
async function testErrorsPerf() {
    section('5. Error Handling & Performance');

    // 404
    const r404 = await req('GET', '/api/nonexistent-route', null, session);
    assert('Unknown route returns 404',      r404.status === 404);

    // Malformed JSON
    const mj = await fetch(`${BASE}/api/compare-with-job`, {
        method: 'POST', redirect: 'manual',
        headers: { 'Content-Type': 'application/json', Cookie: session },
        body: '{bad json'
    });
    assert('Malformed JSON does not crash (< 500)', mj.status < 500);

    // SQL injection
    const sq = await req('POST', '/api/compare-with-job',
        { jobTitle: "'; DROP TABLE users; --" }, session);
    assert('SQL injection handled safely (<500)', sq.status < 500);

    // Password not exposed
    const pd = await req('GET', '/profile-data', null, session);
    assert('Password not in profile-data', !JSON.stringify(pd.json || '').includes('password'));

    // Auth redirect
    const dash = await fetch(`${BASE}/dashboard`, { redirect: 'manual' });
    assert('Unauthenticated /dashboard redirects', [301, 302, 303].includes(dash.status));

    // Performance
    const t0 = Date.now();
    await fetch(`${BASE}/`);
    assert('Home page loads < 3s', Date.now() - t0 < 3000, `${Date.now() - t0}ms`);

    const t1 = Date.now();
    await req('GET', '/session-info', null, session);
    assert('Session info < 1s', Date.now() - t1 < 1000, `${Date.now() - t1}ms`);

    // 5 concurrent requests
    const t2 = Date.now();
    const all = await Promise.all(Array(5).fill(null).map(() =>
        req('GET', '/session-info', null, session)));
    assert('5 concurrent requests all succeed', all.every(r => r.status === 200));
    assert('Concurrent requests resolve < 5s', Date.now() - t2 < 5000, `${Date.now() - t2}ms`);
}

// ── Main ──────────────────────────────────────────────────────
async function main() {
    console.log(`\n╔═══════════════════════════════════════════╗`);
    console.log(`║   CVision Test Suite  —  ${BASE}`);
    console.log(`╚═══════════════════════════════════════════╝`);

    try { await fetch(`${BASE}/`); }
    catch (e) { console.error(`\n  ✗ Cannot reach ${BASE}\n`); process.exit(1); }

    await testAuth();
    await testCV();
    await testJobAPI();
    await testRecruiter();
    await testErrorsPerf();

    const total = passed + failed;
    console.log(`\n${'─'.repeat(48)}`);
    console.log(`  Tests: ${total}  ✅ ${passed}  ❌ ${failed}  (${Math.round(passed/total*100)}%)`);
    if (failures.length) {
        console.log('\n  Failures:');
        failures.forEach(f => console.log(`    • ${f}`));
    }
    console.log(`${'─'.repeat(48)}\n`);

    require('fs').writeFileSync('test-report.json',
        JSON.stringify({ ts: new Date().toISOString(), passed, failed, failures }, null, 2));
    console.log('  Report → test-report.json\n');
    process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error(e.message); process.exit(1); });