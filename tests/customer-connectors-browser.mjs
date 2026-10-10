// Real local production UI; every customer/source API uses synthetic fixtures.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { encode } from 'next-auth/jwt';
for (const file of ['.env', '.env.local', '.env.production', '.env.production.local']) assert.equal(existsSync(file), false, 'Use an unconfigured checkout');
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');
const reserve = createServer().listen(0, '127.0.0.1'); await once(reserve, 'listening');
const port = reserve.address().port; await new Promise(r => reserve.close(r));
const base = `http://127.0.0.1:${port}`, secret = randomBytes(32).toString('hex');
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(PATH|PATHEXT|SYSTEMROOT|WINDIR|TEMP|TMP|COMSPEC|USERPROFILE|APPDATA|LOCALAPPDATA)$/i.test(key)));
Object.assign(env, { NODE_ENV: 'production', NEXTAUTH_URL: base, NEXTAUTH_SECRET: secret, VULN_DISABLE_SCHEDULER: 'true', ELASTIC_VULN_ENABLED: 'true', VULN_REMEDIATION_UI: 'true' });
const server = spawn(process.execPath, ['node_modules/next/dist/bin/next', 'start', '-H', '127.0.0.1', '-p', String(port)], { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
let output = ''; server.stdout.on('data', d => output += d); server.stderr.on('data', d => output += d);
let browser, page, checks = 0; const pass = message => { checks++; console.log('PASS ' + message); };
const artifacts = await mkdtemp(join(tmpdir(), 'vuln2-connectors-browser-'));
const companies = [{ id: 'CO-A', name: 'Fixture Alpha' }, { id: 'CO-B', name: 'Fixture Beta' }, { id: 'CO-EMPTY', name: 'Fixture Empty' }];
const calls = [], errors = [], unexpected = []; let fail = false, pending = false, release;
let previewFailure=false;
let shared = false, partial = true, inventoryRouting = false, inventoryProvider = "automate", spotlightRouting = false, scannerRouting = false, scannerProvider = "nessus";
function status(id) {
  const result = { companyId: id, companyName: companies.find(c => c.id === id).name, checkedAt: '2026-10-09T19:00:00Z', registryAvailable: id !== 'CO-A',
    items: id === 'CO-EMPTY' ? [] : [{ id: id+'-record', provider: inventoryRouting ? inventoryProvider : id === 'CO-A' ? 'defender' : 'crowdstrike', evidence: 'Saved customer connection', configuration: 'Configuration recorded',
      review: inventoryRouting ? 'Inventory route approved' : id === 'CO-A' ? 'Not imported for review' : 'Needs review', scope: inventoryRouting ? 'A separate inventory import approval is recorded. See routing details for its current state.' : 'Tenant recorded; scope verification pending.', reviewedAt: null,
      data: {domains:inventoryRouting?['inventory']:['endpoint-findings'],storage:inventoryRouting?'Existing platform inventory':'Completed source SQL generations',lifecycle:inventoryRouting?'Reviewed customer ownership':'Only complete imports',routing:inventoryRouting ? 'Approved for inventory routing; the provider switch is on. All routes are checked again when an import starts. This does not confirm a successful import.' : 'Customer scope has not been reviewed.'},
      reasons: ['Verify the vendor tenant and how this source contributes data.', 'Source evidence has changed since the saved review.'] }] };
  if(spotlightRouting && result.items.length){result.items[0].review='Inventory route approved; Spotlight route approved';
    result.items[0].scope='Separate inventory and Spotlight approvals are recorded. See routing details for each state.';
    result.items[0].data.routing+=' Approval recorded; the Spotlight routing switch is off. Existing import routing still applies.';}
  if(scannerRouting && result.items.length){result.items[0].provider=scannerProvider;result.items[0].review='Scanner route approved';
    result.items[0].scope='A separate scanner source and target approval is recorded. See routing details for its current state.';
    result.items[0].data={domains:['endpoint-findings'],storage:'Existing platform findings',lifecycle:'Reviewed folder and target ownership',routing:'Approved for scanner routing; the provider switch is on. This does not confirm a successful import.'};}
  return result;
}
try {
  let ready = false;
  for (let i = 0; i < 100; i++) { try { if ((await fetch(base+'/login')).ok) { ready = true; break; } } catch {} await delay(100); }
  assert.ok(ready, output);
  const anonymous = await fetch(base+'/api/elastic-dashboard/customer-connectors?companyId=CO-A', { redirect: 'manual' });
  assert.ok([401, 307, 302].includes(anonymous.status));
  browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHANNEL ? {channel:process.env.PLAYWRIGHT_CHANNEL} : {}) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 } });
  const token = await encode({ secret, token: { name: 'Fixture member', orgMember: true, orgRole: 'MEMBER' }, maxAge: 300 });
  await context.addCookies([{ name: 'next-auth.session-token', value: token, url: base }]);
  page = await context.newPage(); page.setDefaultTimeout(10000); page.on('pageerror', e => errors.push(e.message));
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== base) return route.abort();
    if (!url.pathname.startsWith('/api/')) return route.continue();
    calls.push({ path: url.pathname, company: url.searchParams.get('companyId'), method: request.method() });
    const json = (data, code = 200) => route.fulfill({ status: code, contentType: 'application/json', body: JSON.stringify(data) }).catch(() => {});
    if (url.pathname === '/api/auth/session') return json({ user: { name: 'Fixture member' }, expires: '2099-01-01T00:00:00Z' });
    if (shared) {
      if (url.pathname === '/api/connectors') return json({connectors:[{id:'nessus',name:'Fixture Nessus',vendor:'Fixture',kind:'Scanner',
        description:'Synthetic scanner',capabilities:[],envVars:[],configured:true,status:'Connected',docsUrl:'https://example.invalid'}]});
      if (url.pathname === '/api/integrations') return json({integrations:[]});
      if (url.pathname === '/api/elastic-vulnerabilities/status') return json({enabled:false});
      if (url.pathname === '/api/osint/preview') return previewFailure?json({error:'OSINT routing unavailable'},503):json({preview:{companies:1,domainsTotal:1,perCompany:[{company:'Fixture Beta',domains:['fixture.invalid']}]}});
      if (url.pathname === '/api/connectors/sync-all' && request.method() === 'GET') return json({status:null});
      if (url.pathname === '/api/nessus/health') return json({reachable:true,status:'Connected'});
      if (url.pathname === '/api/nessus/import' && request.method() === 'POST') return json({result:{scansImported:1,findingsImported:5,skipped:partial?1:0,
        errors:partial?['Private provider response that must not be displayed']:[]}});
    }
    if (url.pathname === '/api/elastic-dashboard/customer-connectors') {
      if (url.searchParams.get('setup') === '1') return json({ companies });
      const id = url.searchParams.get('companyId');
      if (pending && id === 'CO-A') { pending = false; await new Promise(r => release = r); }
      return fail ? json({ error: 'Fixture metadata refresh failed.' }, 503) : json(status(id));
    }
    unexpected.push(url.pathname); return json({ error: 'Unexpected request' }, 500);
  });
  await page.goto(base+'/connectors');
  const select = page.getByLabel('Customer', { exact: true }); await select.waitFor();
  assert.equal(calls.filter(c => c.company).length, 0); assert.equal(await select.count(), 1);
  await select.selectOption('CO-A'); await page.getByRole('heading', { name: 'Microsoft Defender', exact: true }).waitFor();
  await page.getByText('Registry review has not been initialized.', { exact: false }).waitFor();
  assert.ok(page.url().includes('companyId=CO-A'));
  assert.ok((await page.getByRole('link', { name: 'Remediation', exact: true }).getAttribute('href')).includes('companyId=CO-A'));
  assert.ok((await page.getByRole('link', { name: 'Shared connector tools' }).getAttribute('href')).includes('view=shared'));
  await page.getByText('Review details (2)', { exact: true }).click();
  await page.getByText('Verify the vendor tenant and how this source contributes data.', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: /Approve|Enable|Configure|Sync|Scan/ }).count(), 0);
  await page.getByText('How this source is used', {exact:true}).click();
  await page.getByText('Completed source SQL generations', {exact:false}).waitFor();
  await page.screenshot({ path: join(artifacts, 'customer-connectors-desktop.png'), fullPage: true });
  pass('single customer selector, scoped links, review explanations and missing-registry state');

  fail = true; await page.getByRole('button', { name: 'Refresh status' }).click();
  await page.getByRole('alert').filter({ hasText: 'Fixture metadata refresh failed.' }).waitFor();
  await page.getByText('Previously loaded configuration is shown below.', { exact: false }).waitFor();
  await page.getByRole('heading', { name: 'Microsoft Defender', exact: true }).waitFor();
  fail = false; pending = true; await page.getByRole('button', { name: 'Refresh status' }).click();
  for (let i = 0; i < 50 && !release; i++) await delay(20); assert.ok(release);
  await page.getByLabel('Customer', { exact: true }).selectOption('CO-B');
  await page.getByRole('heading', { name: 'CrowdStrike', exact: true }).waitFor();
  release(); await delay(100);
  assert.equal(await page.getByRole('heading', { name: 'Microsoft Defender', exact: true }).count(), 0);
  await page.goBack(); await page.getByRole('heading', { name: 'Microsoft Defender', exact: true }).waitFor();
  await page.getByLabel('Customer', { exact: true }).selectOption('CO-EMPTY');
  await page.getByText('No customer-specific connector mapping or proposal is recorded.', { exact: false }).waitFor();
  pass('refresh failure retains same-customer evidence; late responses and browser history respect customer scope');

  await page.getByLabel('Customer', { exact: true }).selectOption('CO-B'); await page.getByRole('heading', { name: 'CrowdStrike', exact: true }).waitFor();
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  await page.screenshot({ path: join(artifacts, 'customer-connectors-mobile.png'), fullPage: true });
  assert.ok(calls.every(c => c.method === 'GET')); assert.deepEqual(unexpected, []); assert.deepEqual(errors, []);
  pass('mobile fit; no mutation, global connector health probe, scan or sync request');
  inventoryRouting=true;
  for(const [provider,label] of [['automate','ConnectWise Automate'],['tidal','Tidal'],['crowdstrike','CrowdStrike']]) {
    inventoryProvider=provider;await page.getByRole('button',{name:'Refresh status'}).click();
    await page.getByRole('heading',{name:label,exact:true}).waitFor();
    await page.getByText('Inventory route approved',{exact:true}).waitFor();
    await page.getByText('How this source is used',{exact:true}).click();
    await page.getByText('Approved for inventory routing; the provider switch is on.',{exact:false}).waitFor();
    assert.equal(await page.getByRole('button',{name:/Approve|Enable|Configure|Sync|Scan/}).count(),0);
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  }
  await page.screenshot({path:join(artifacts,'inventory-route-status-mobile.png'),fullPage:true});
  pass('Automate, Tidal and CrowdStrike inventory approvals display without implying import health or granting new controls');
  spotlightRouting=true;await page.getByRole('button',{name:'Refresh status'}).click();
  await page.getByText('Inventory route approved; Spotlight route approved',{exact:true}).waitFor();
  await page.getByText('Separate inventory and Spotlight approvals are recorded.',{exact:false}).waitFor();
  await page.getByText('the Spotlight routing switch is off.',{exact:false}).waitFor();
  assert.equal(await page.getByRole('combobox').count(),1);
  await page.screenshot({path:join(artifacts,'spotlight-route-status-mobile.png'),fullPage:true});
  pass('Spotlight approval displays separately from host inventory with no extra selector or import control');
  scannerRouting=true;await page.getByRole('button',{name:'Refresh status'}).click();
  await page.getByText('Scanner route approved',{exact:true}).waitFor();
  await page.getByText('A separate scanner source and target approval is recorded.',{exact:false}).waitFor();
  assert.equal(await page.getByRole('combobox').count(),1);
  await page.screenshot({path:join(artifacts,'scanner-route-status-mobile.png'),fullPage:true});
  pass('Nessus approval displays without private targets, another selector or new operational controls');
  for(const provider of ['spiderfoot','artemis','zap','vulners']){
    scannerProvider=provider;await page.getByRole('button',{name:'Refresh status',exact:true}).click();
    await page.getByText(provider==='spiderfoot'?'SpiderFoot':provider,{exact:true}).waitFor();await page.getByText('Scanner route approved',{exact:true}).waitFor();
    assert.equal(await page.getByRole('combobox').count(),1);
  }
  await page.screenshot({path:join(artifacts,'osint-route-status-mobile.png'),fullPage:true});
  pass('SpiderFoot, Artemis, ZAP and Vulners approvals display within the same customer selector and permissions');

  shared = true; await page.setViewportSize({width:1440,height:1050});
  await page.goto(base+'/connectors?view=shared&companyId=CO-B');
  await page.getByRole('heading',{name:'Fixture Nessus',exact:true}).click();
  await page.getByRole('button',{name:'Sync now',exact:true}).click();
  const warning=page.getByText(/Needs attention: 1 import error/);await warning.waitFor();
  assert.match(await warning.getAttribute('class'),/ff8a8a/);
  assert.ok(!(await page.locator('body').innerText()).includes('Private provider response'));
  await page.screenshot({path:join(artifacts,'import-partial-warning.png'),fullPage:true});
  partial=false;await page.getByRole('button',{name:'Sync now',exact:true}).click();
  const success=page.getByText('Synced — 5 findings, 1 scans.',{exact:true});await success.waitFor();
  assert.match(await success.getAttribute('class'),/emerald/);
  assert.equal(calls.filter(c=>c.method==='POST').length,2);assert.deepEqual(unexpected,[]);assert.deepEqual(errors,[]);
  pass('shared tools display partial imports as attention-needed, redact provider details and recover after a successful fixture sync');
  previewFailure=true;await page.reload();await page.getByRole('alert').filter({hasText:'OSINT target preview is unavailable'}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Run OSINT scans',exact:true}).isDisabled(),true);
  previewFailure=false;await page.reload();await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent==='Run OSINT scans'&&!b.disabled));
  assert.equal(calls.filter(c=>c.method==='POST').length,2);
  pass('OSINT preview failure is visible and disables launch; restored preview recovers without launching scans');

  await writeFile(join(artifacts, 'result.json'), JSON.stringify({ checks, unexpected, errors, calls }, null, 2));
  console.log(JSON.stringify({ passed: checks, artifacts }));
} catch (error) {
  await page?.screenshot({ path: join(artifacts, 'failure.png'), fullPage: true }).catch(() => {});
  console.error(JSON.stringify({ artifacts, url: page?.url(), errors, unexpected, calls, body: (await page?.locator('body').innerText().catch(() => ''))?.slice(0, 1500) }));
  throw error;
} finally {
  await browser?.close(); server.kill(); await once(server, 'exit').catch(() => {});
}
