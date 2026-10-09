// Exercises the built application on loopback, with disposable sessions and no
// production configuration, database, provider credentials or ticket delivery.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { encode } from 'next-auth/jwt';

for (const file of ['.env', '.env.local', '.env.production', '.env.production.local']) {
  assert.equal(existsSync(file), false, `Run this test in a clean checkout without ${file}.`);
}

for (const enabled of [false, true]) {
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const base = `http://127.0.0.1:${port}`, secret = randomBytes(32).toString('hex');
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    /^(PATH|PATHEXT|SYSTEMROOT|WINDIR|TEMP|TMP|COMSPEC|USERPROFILE|APPDATA|LOCALAPPDATA)$/i.test(key)));
  Object.assign(env, { NODE_ENV: 'production', NEXTAUTH_URL: base, NEXTAUTH_SECRET: secret,
    VULN_DISABLE_SCHEDULER: 'true', ELASTIC_VULN_ENABLED: 'true', VULN_REMEDIATION_UI: String(enabled) });
  const child = spawn(process.execPath, ['node_modules/next/dist/bin/next', 'start', '-H', '127.0.0.1', '-p', String(port)],
    { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', data => { output += data; });
  child.stderr.on('data', data => { output += data; });
  try {
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      try { if ((await fetch(`${base}/login`)).ok) { ready = true; break; } } catch {}
      await delay(100);
    }
    assert.ok(ready, `Local server failed to start: ${output}`);
    const token = await encode({ secret, token: { name: 'Local test', orgMember: true, orgRole: 'MEMBER' }, maxAge: 120 });
    const headers = { cookie: `next-auth.session-token=${token}` };
    assert.equal((await fetch(`${base}/remediation`, { redirect: 'manual' })).status, 307);
    assert.equal((await fetch(`${base}/api/elastic-vulnerabilities/status`)).status, 401);
    for(const endpoint of ['customer-cve','customer-threat-intelligence']) {
      assert.equal((await fetch(`${base}/api/elastic-dashboard/${endpoint}`)).status,401);
      const scoped=await fetch(`${base}/api/elastic-dashboard/${endpoint}?companyId=&cve=CVE-2026-1234`,{headers});
      assert.equal(scoped.status,enabled?400:404);
    }
    // Cross-origin mutation cannot prepare a draft, even with a valid member session.
    assert.equal((await fetch(`${base}/api/elastic-dashboard/customer-cve`,{method:'POST',
      headers:{...headers,origin:'https://other.invalid','content-type':'application/json'},
      body:JSON.stringify({companyId:'CO-230784',cve:'CVE-2026-1234'})})).status,403);
    assert.deepEqual(await (await fetch(`${base}/api/elastic-vulnerabilities/status`, { headers })).json(),
      { enabled: true, ...(enabled ? { remediationEnabled: true } : {}) });
    // The existing reporting route remains reachable in both modes.
    assert.equal((await fetch(`${base}/reporting`, { headers })).status, 200);
    const response = await fetch(`${base}/remediation`, { headers });
    assert.equal(response.status, enabled ? 200 : 404);
    if (enabled) {
      const empty = await response.text();
      assert.match(empty, /Choose a customer/);
      assert.doesNotMatch(empty, /aria-label="Patching posture/);
      for (const view of ['overview', 'prioritize', 'tickets']) {
        const result = await fetch(`${base}/remediation?companyId=CO-230784&view=${view}`, { headers });
        assert.equal(result.status, 200);
        const html = await result.text();
        assert.match(html, /Remediation views/);
        assert.equal(html.includes('aria-label="Patching posture'), view === 'prioritize');
        assert.equal(html.includes('id="consolidation-review"'), view === 'tickets');
        assert.equal(html.includes('aria-label="Threat Intelligence"'),view === 'prioritize');
        assert.equal(html.includes("Loading this customer&#x27;s saved tiles"), view === 'overview');
      }
    }
    console.log(`Remediation HTTP smoke passed: feature ${enabled ? 'on' : 'off'}`);
  } finally {
    const stopped = once(child, 'exit'); child.kill(); await stopped;
  }
}
