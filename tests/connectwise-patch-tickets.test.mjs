// node --experimental-vm-modules --test tests/connectwise-patch-tickets.test.mjs
// Optional database tests require PATCH_TICKET_TEST_DATABASE_URL pointing at a disposable local database.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import ts from 'typescript';
import pg from 'pg';

function loader(overrides = {}) {
 const cache=new Map();
 async function getModule(path) {
  path=resolve(path);if(cache.has(path))return cache.get(path);
  const promise=(async()=>new SourceTextModule(ts.transpileModule(await readFile(path,"utf8"),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path}))();
  cache.set(path,promise);return promise;
 }
 const synthetic=values=>new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});
 async function linker(name,parent) {
  if(overrides[name])return synthetic(overrides[name]);
  if(name.startsWith("."))return getModule(resolve(dirname(parent.identifier),/\.(?:mjs|js|ts)$/.test(name)?name:`${name}.ts`));
  if(name.startsWith("@/"))return getModule(resolve(".",/\.(?:mjs|js|ts)$/.test(name)?name.slice(2):`${name.slice(2)}.ts`));
  const imported=await import(name);return synthetic(name === "rrule"?{...imported.default,...imported}:imported);
 }
 return async path=>{const m=await getModule(path);if(m.status === "unlinked")await m.link(linker);await m.evaluate();return m.namespace;};
}
const connection = { endpoint: 'https://api-na.myconnectwise.net/v4_6_release/apis/3.0', companyId: 'test-company', clientId: 'test-client', publicKey: 'test-public', privateKey: 'test-private+/=' };
const originalSecret = process.env.NEXTAUTH_SECRET;
process.env.NEXTAUTH_SECRET = 'local-connectwise-test-secret-only-123456789';
test.after(() => { if (originalSecret === undefined) delete process.env.NEXTAUTH_SECRET; else process.env.NEXTAUTH_SECRET = originalSecret; });
let replies = [], calls = [], resolvedAddress = '8.8.8.8';
const loadClient = loader({
  'node:dns/promises': { lookup: async () => ({ address: resolvedAddress, family: 4 }) },
  'node:https': { request: (url, options, callback) => {
    const req = new EventEmitter(); req.destroy = () => { req.emit('error', new Error('test')); req.emit('close'); };
    req.end = payload => { calls.push({ url, options, payload }); queueMicrotask(() => {
      const reply = replies.shift(); if (!reply) return req.destroy();
      const res = new EventEmitter(); res.statusCode = reply.status ?? 200; callback(res);
      res.emit('data', Buffer.from(JSON.stringify(reply.body))); res.emit('end'); req.emit('close');
    }); };
    return req;
  } },
});
const client = await loadClient('lib/connectwise-client.ts');
const dashboard = await loadClient('lib/elastic-dashboard.ts');

test('credentials encrypt, reject tampering, support private key punctuation and redact errors', () => {
  assert.deepEqual(client.parseCWConnection(connection), connection);
  const sealed = client.sealCWConnection(connection); assert.ok(!sealed.includes(connection.privateKey));
  assert.deepEqual(client.openCWConnection(sealed), connection);
  assert.throws(() => client.openCWConnection(sealed.slice(0, -5) + 'AAAAA'), /keys again/);
  const error = client.cwFailure(400, { message: `${connection.privateKey} ${connection.publicKey} Basic secret` }, connection);
  assert.ok(!error.message.includes(connection.privateKey)); assert.ok(!error.message.includes(connection.publicKey)); assert.equal(error.uncertain, false);
  assert.equal(client.normalizeCWEndpoint('https://na.myconnectwise.net'), connection.endpoint);
  assert.throws(() => client.normalizeCWEndpoint('http://localhost'), /HTTPS/);
});
test('CW_AUTH accepts raw or Basic-prefixed Base64 and rejects malformed or unsafe values without echoing secrets', () => {
  const raw = `${connection.companyId}+${connection.publicKey}:${connection.privateKey}`;
  const encoded = Buffer.from(raw).toString('base64');
  const expected = { companyId: connection.companyId, publicKey: connection.publicKey, privateKey: connection.privateKey };
  for (const value of [encoded, ` Basic ${encoded} `, encoded.replace(/=+$/, '')]) assert.deepEqual(client.parseCWAuth(value), expected);
  for (const value of ['', 'Test', `CW_AUTH=${encoded}`, 'Bearer '+encoded, encoded+'!', 123, Buffer.from('company:key').toString('base64'), Buffer.from('company+key:').toString('base64'), Buffer.from('company+key:secret\r\n').toString('base64')]) {
    assert.throws(() => client.parseCWAuth(value), error => !error.message.includes(encoded) && /CW_AUTH/.test(error.message));
  }
  const saved = client.parseCWConnection({ ...connection, ...client.parseCWAuth(encoded), authMode: 'encoded' });
  assert.equal(client.openCWConnection(client.sealCWConnection(saved)).authMode, 'encoded');
  assert.ok(!client.cwFailure(403, { message: encoded }, saved).message.includes(encoded));
});
test('real list names, selected values past page one, board status filtering and reference identity', async () => {
  calls = []; replies = [{ body: Array.from({ length: 100 }, (_, i) => ({ id: i + 1, name: `Real board ${i + 1}` })) }, { body: { id: 500, name: 'Actual patch board' } }];
  const result = await client.cwOptions(connection, 'boards', undefined, 1, '', 500);
  assert.equal(result.options.at(-1).name, 'Actual patch board'); assert.equal(result.more, true);
  assert.match(calls[0].url.pathname, /\/service\/info\/boards$/);
  assert.match(calls[1].url.pathname, /\/service\/info\/boards\/500$/);
  replies = [{ body: [{ id: 1, name: 'Closed', closedStatus: true }, { id: 2, name: 'Ready to patch' }] }];
  assert.deepEqual((await client.cwOptions(connection, 'statuses', 500)).options, [{ id: 2, name: 'Ready to patch' }]);
  await assert.rejects(client.cwOptions(connection, '__proto__'), /Invalid/);
  replies = Array.from({ length: 3 }, () => ({ body: { id: 999, name: 'Wrong reference' } }));
  await assert.rejects(client.validateCWRouting(connection, { boardId: 1, statusId: 2, priorityId: 3 }), /unavailable/);
});
test('routing uses defaults without reading priority or status setup when no priority is chosen', async () => {
  assert.deepEqual(client.parseRouting({ companyId: 30, boardId: 10, statusId: 11 }), { companyId: 30, boardId: 10 });
  calls = []; replies = [{ body: { id: 10, name: 'Patch board' } }];
  const labels = await client.validateCWRouting(connection, { boardId: 10 });
  assert.equal(labels.board.name, 'Patch board');
  assert.deepEqual(calls.map(c => c.url.pathname.replace('/v4_6_release/apis/3.0', '')), ['/service/info/boards/10']);
  assert.ok(calls.every(c => c.options.method === 'GET'));
  calls = []; replies = [{ status: 403, body: { message: 'You do not have security permission to perform this action.' } }];
  await assert.rejects(client.cwOptions(connection, 'boards'), /HTTP 403/);
  assert.equal(calls.length, 1, 'No fallback to the more privileged setup endpoint and no trial ticket');
});

test('selected priority is retained and validated against active ConnectWise references', async () => {
  const routing = { companyId: 30, boardId: 10, priorityId: 21 };
  assert.deepEqual(client.parseRouting({ ...routing, statusId: 11 }), routing);
  for (const priorityId of [0, -1, 1.5, '21', null, {}, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => client.parseRouting({ ...routing, priorityId }), /priority/i);
  }
  calls = []; replies = [{ body: { id: 10, name: 'Patch board' } }, { body: { id: 21, name: 'Priority 2 - High' } }];
  const labels = await client.validateCWRouting(connection, { boardId: 10, priorityId: 21 });
  assert.deepEqual(labels.priority, { id: 21, name: 'Priority 2 - High' });
  assert.match(calls[1].url.pathname, /\/service\/priorities\/21$/);
  for (const invalid of [{ id: 21, name: 'Inactive', inactiveFlag: true }, { id: 22, name: 'Wrong ID' }, { id: 21, name: '' }]) {
    replies = [{ body: { id: 10, name: 'Patch board' } }, { body: invalid }];
    await assert.rejects(client.validateCWRouting(connection, { boardId: 10, priorityId: 21 }), /priority.*unavailable/);
  }
});

for (const grouped of [false, true]) test(`${grouped ? 'group' : 'CVE'} creation sends selected priority, saves returned priority, and never posts an invalid selection`, async () => {
  for (const mode of ['default', 'selected', 'unavailable', 'stale']) {
    const id = randomUUID(), now = new Date().toISOString(), table = grouped ? 'patch_group_ticket_requests' : 'patch_ticket_requests';
    const row = { id, cve: 'CVE-2026-1234', cves: ['CVE-2026-1234'], state: 'prepared', review_state: 'approved',
      tenant_ids: ['tenant'], tenant_id: 'tenant', crowdstrike_revision: 1, prepared_at: now, updated_at: now,
      host_count: 1, packet: { csv: 'host\nfixture', hostScope: ['fixture'], label: 'Fixture update' } };
    const dbCalls = [], posts = [];
    const db = { connect: async () => ({ query: db.query, release() {} }), query: async (sql, args = []) => {
      dbCalls.push({ sql, args });
      if (sql.startsWith('SELECT * FROM patch_connectwise_connection')) return { rows: [{ secret: client.sealCWConnection(connection), target: client.cwTarget(connection), revision: 1, defaults: {} }] };
      if (sql.startsWith('SELECT revision')) return { rows: [{ revision: 1 }] };
      if (sql.startsWith('SELECT id,ticket_id')) return { rows: [] };
      if (sql.startsWith('SELECT ') && sql.includes(`FROM ${table} WHERE id=$1`)) return { rows: [{ ...row }] };
      if (sql.startsWith(`UPDATE ${table} SET state='creating'`)) Object.assign(row, { state: 'creating', created_by: args[1], cw_target: args[2], cw_revision: args[3], company_id: args[4], routing: JSON.parse(args[5]), title: args[6], body: args[7] });
      if (sql.startsWith(`UPDATE ${table} SET labels=`)) row.labels = JSON.parse(args[1]);
      if (sql.startsWith(`UPDATE ${table} SET state='created'`)) Object.assign(row, { state: 'created', ticket_id: args[1], ticket_url: args[2], ticket_status: args[3], closed: args[4], attachment_state: 'pending', ticket_priority_id: args[5], ticket_priority_name: args[6] });
      if (sql.startsWith(`UPDATE ${table} SET attachment_state='uploading'`)) { row.attachment_state = 'uploading'; return { rows: [{ ...row }] }; }
      if (sql.startsWith(`UPDATE ${table} SET attachment_state='attached'`)) row.attachment_state = 'attached';
      if (sql.startsWith(`UPDATE ${table} SET state=CASE`)) { row.state = row.ticket_id ? 'created' : args[1]; row.last_error = args[2]; }
      return { rows: [], rowCount: 1 };
    } };
    let ticket;
    const api = await loader({
      './elastic-dashboard': dashboard,
      './elastic-dashboard-store': { dashboardDatabase: async () => db, assertPatchRequestScope: async () => {}, verifyAgainstCrowdStrike: async () => assert.fail('Unexpected provider call') },
      './reporting-tenant-scope': { customerFalconTenantIds: () => [] },
      './reporting-direct-sources': { atlasFalconReviewPacket: group => group },
      './customer-consolidation-hold': { requiresConsolidationManualReview: () => false },
      './connectwise-client': { ...client,
        validateCWRouting: async (c, routing) => {
          calls = []; replies = [{ body: { id: 30, name: 'Customer' } }, { body: { id: 10, name: 'Patch board' } }];
          if (routing.priorityId) replies.push({ body: { id: 21, name: 'Priority 2 - High', inactiveFlag: mode === 'unavailable' } });
          return client.validateCWRouting(c, routing);
        },
        cwRequest: async (_c, path, method, body) => {
          if (method === 'POST') {
            assert.equal(path, '/service/tickets'); posts.push(body);
            ticket = { id: 100, company: body.company, externalXRef: body.externalXRef, priority: { id: body.priority?.id ?? 24, name: body.priority ? 'Priority 2 - High' : 'Priority 4 - Low' } };
          }
          return ticket;
        },
        uploadPatchCsv: async () => 700,
      },
    })(`lib/${grouped ? 'patch-group-ticket-store' : 'patch-ticket-store'}.ts`);
    const create = grouped ? api.createGroupTicket : api.createPatchTicket;
    const read = grouped ? api.readGroupTicket : api.readPatchTicket;
    const payload = { title: 'Fixture ticket', body: 'Fixture contents', connectionRevision: mode === 'stale' ? 2 : 1,
      routing: { companyId: 30, boardId: 10, ...(mode !== 'default' ? { priorityId: 21 } : {}) } };
    if (mode === 'stale') { await assert.rejects(create(id, payload, 'analyst'), /connection changed/); assert.equal(posts.length, 0); continue; }
    await create(id, payload, 'analyst');
    for (let i = 0; i < 100 && row.attachment_state !== 'attached' && row.state !== 'failed'; i++) await new Promise(r => setTimeout(r, 10));
    if (mode === 'unavailable') { assert.equal(row.state, 'failed'); assert.match(row.last_error, /priority.*unavailable/); assert.equal(posts.length, 0); continue; }
    assert.equal(row.attachment_state, 'attached'); assert.equal(posts.length, 1);
    assert.ok(!('status' in posts[0]));
    if (mode === 'default') assert.ok(!('priority' in posts[0])); else assert.deepEqual(posts[0].priority, { id: 21 });
    const { request } = await read(id);
    assert.equal(request.priorityId, ticket.priority.id); assert.equal(request.priorityName, ticket.priority.name);
    assert.equal(row.routing.priorityId, payload.routing.priorityId);
    await create(id, payload, 'analyst'); assert.equal(posts.length, 1, 'Repeated submission must not create another ticket');
  }
});
test('HTTP transport pins public DNS, sends authentication, rejects redirects, never retries POST', async () => {
  calls = []; replies = [{ status: 502, body: { message: 'Unavailable' } }];
  await assert.rejects(client.cwRequest(connection, '/service/tickets', 'POST', { summary: 'test' }), e => e.uncertain === true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.headers.clientId, connection.clientId);
  calls[0].options.lookup('ignored', {}, (error, address) => { assert.equal(error, null); assert.equal(address, '8.8.8.8'); });
  replies = [{ status: 302, body: {} }]; await assert.rejects(client.cwRequest(connection, '/service/boards'), /HTTP 302/);
  assert.equal(calls.length, 2);
  resolvedAddress = '127.0.0.1'; await assert.rejects(client.cwRequest(connection, '/service/boards'), /public HTTPS/); resolvedAddress = '8.8.8.8';
  assert.equal(calls.length, 2);
});
test('CSV upload reconciles an existing attachment and otherwise sends multipart ticket document', async () => {
  const id = randomUUID(), title = `CVE-2026-1234 patch request ${id}`;
  calls = []; replies = [{ body: [{ id: 99, title }] }];
  assert.equal(await client.uploadPatchCsv(connection, 33, id, 'CVE-2026-1234', 'host\nserver'), 99); assert.equal(calls.length, 1);
  replies = [{ body: [] }, { body: { id: 100 } }];
  assert.equal(await client.uploadPatchCsv(connection, 33, id, 'CVE-2026-1234', 'host\nserver'), 100);
  const upload = calls.at(-1); assert.match(upload.options.headers['Content-Type'], /multipart/);
  assert.match(upload.payload.toString(), /name="recordType"\r\n\r\nTicket/); assert.match(upload.payload.toString(), /name="recordId"\r\n\r\n33/);
});

test('durable ticket lifecycle and duplicate protection in PostgreSQL', { skip: !process.env.PATCH_TICKET_TEST_DATABASE_URL }, async t => {
  const url = new URL(process.env.PATCH_TICKET_TEST_DATABASE_URL);
  assert.ok(['localhost', '127.0.0.1'].includes(url.hostname) && url.pathname === '/patch_ticket_test', 'Only the disposable local test database is allowed');
  const db = new pg.Pool({ connectionString: url.toString() });
  let mode = 'ok', uploads = 0, posts = 0, ticketSequence = 1000, uploadFail = false, pausePost;
  let scopeAllowed = true, revokeDuringRouting = false;
  const tickets = new Map();
  const store = await loader({
    './elastic-dashboard-store': { dashboardDatabase: async () => db, assertPatchRequestScope:async()=>{if(!scopeAllowed)throw new Error('Fixture customer approval revoked');}, verifyAgainstCrowdStrike:async()=>{throw new Error('No live CrowdStrike calls allowed in ticket tests');} },
    './connectwise-client': { ...client,
      cwOptions: async () => ({ options: [{ id: 10, name: 'Customer patching' }], more: false, page: 1 }),
      validateCWRouting: async (_c, r) => {if(revokeDuringRouting)scopeAllowed=false;return { company: { id: r.companyId, name: 'Actual customer' }, board: { id: r.boardId, name: 'Customer patching' } };},
      cwRequest: async (_c, path, method, body) => {
        if (method === 'POST') { assert.ok(!('status' in body), 'ConnectWise must choose the initial status'); assert.ok(!('priority' in body), 'ConnectWise must choose the priority'); posts++; if (pausePost) await pausePost;
          if (mode === 'rejected') throw new client.CWRequestError('Bad routing', false);
          const ticket = { id: ++ticketSequence, externalXRef: body.externalXRef, company: body.company, status: { name: 'New' }, closedFlag: false }; tickets.set(ticket.id, ticket);
          if (mode === 'uncertain') throw new client.CWRequestError('Lost response', true);
          return ticket;
        }
        return tickets.get(Number(path.split('/').at(-1)));
      },
      findCWRequest: async (_c, reference) => [...tickets.values()].find(x => x.externalXRef === reference) ?? null,
      uploadPatchCsv: async () => { uploads++; if (uploadFail) throw new client.CWRequestError('Upload failed', true); return 700; },
    },
  })('lib/patch-ticket-store.ts');
  await store.patchTicketDatabase();
  await db.query("TRUNCATE patch_ticket_requests,patch_connectwise_connection,patch_ticket_audit; CREATE TABLE IF NOT EXISTS dashboard_source_connections(source TEXT PRIMARY KEY,revision INT); INSERT INTO dashboard_source_connections VALUES('crowdstrike',1) ON CONFLICT(source) DO UPDATE SET revision=1");
  const packet = { cve: 'CVE-2026-1234', collectedAt: new Date().toISOString(), region: 'us-1', hostCount: 1, findingCount: 1, csvRows: 1, title: 'Patch', body: 'Recommended remediation only', csv: 'host\nserver', warnings: [], tenantIds: ['a'.repeat(32)], hostScope: ['tenant:device'] };
  const draft = async (extra = {}) => { const id = randomUUID(); await store.persistPreparedPatch(id, { ...packet, ...extra }, 'user@example.test', 1); return id; };
  const submit = { title: 'Patch CVE', body: packet.body, connectionRevision: 1, routing: { companyId: 30, boardId: 10, statusId: 11 } };
  async function waitFor(id, predicate) { for (let i = 0; i < 200; i++) { const { request } = await store.readPatchTicket(id); if (predicate(request)) { await new Promise(r => setTimeout(r, 20)); return request; } await new Promise(r => setTimeout(r, 10)); } assert.fail('Worker did not reach expected state'); }
  try {
    await store.saveCWSettings(connection, 'admin@example.test');
    const settings = await store.readCWSettings(); assert.equal(settings.revision, 1); assert.ok(!JSON.stringify(settings).includes('test-private')); assert.ok(!('publicKey' in settings));
    await store.saveCWDefaults({ boardId: 10, statusId: 11, priorityId: 12 }, 'member');
    assert.deepEqual((await store.readCWSettings()).defaults, { boardId: 10 }, 'Old status/priority choices must not override ConnectWise defaults');
    await t.test('revoked customer approval stops delivery before queueing and before the creation POST', async () => {
      const before = posts, rejected = await draft({hostScope:['tenant:scope-check']});
      scopeAllowed=false;
      await assert.rejects(()=>store.createPatchTicket(rejected,submit,'member'),/approval revoked/);
      assert.equal((await store.readPatchTicket(rejected)).request.state,'prepared');assert.equal(posts,before);
      scopeAllowed=true;revokeDuringRouting=true;
      await store.createPatchTicket(rejected,submit,'member');
      await waitFor(rejected,r=>r.state==='failed');assert.equal(posts,before);
      scopeAllowed=true;revokeDuringRouting=false;
    });
    await t.test('concurrent same scope and repeated same ID create exactly one ticket', async () => {
      const first = await draft(), second = await draft(); let release; pausePost = new Promise(r => release = r);
      const results = await Promise.allSettled([store.createPatchTicket(first, submit, 'member'), store.createPatchTicket(second, submit, 'member')]);
      assert.equal(results.filter(x => x.status === 'fulfilled').length, 1);
      const active = results[0].status === 'fulfilled' ? first : second;
      await store.createPatchTicket(active, submit, 'member'); release(); pausePost = undefined;
      const request = await waitFor(active, r => r.attachmentState === 'attached'); assert.equal(posts, 1); assert.equal(request.company, 'Actual customer');
      assert.equal((await store.readPatchTicket(active, true)).packet.csv, packet.csv);
      tickets.get(request.ticketId).closedFlag = true;
      assert.equal((await store.patchTicketAction(active, 'check-status', 'member')).request.closed, true);
    });
    await t.test('CSV failure preserves ticket and retry uploads only', async () => {
      uploadFail = true; const id = await draft(); await store.createPatchTicket(id, submit, 'member');
      const saved = await waitFor(id, r => r.state === 'created' && r.attachmentState === 'pending' && r.error); const before = posts;
      uploadFail = false; await store.patchTicketAction(id, 'retry-attachment', 'member');
      const complete = await waitFor(id, r => r.attachmentState === 'attached'); assert.equal(posts, before); assert.equal(complete.ticketId, saved.ticketId);
    });
    await t.test('lost response reconciles reference without reposting', async () => {
      mode = 'uncertain'; const id = await draft({ hostScope: ['tenant:device2'] }); await store.createPatchTicket(id, submit, 'member');
      await waitFor(id, r => r.state === 'uncertain'); const before = posts;
      await store.createPatchTicket(id, submit, 'member'); assert.equal(posts, before);
      const recovered = await store.patchTicketAction(id, 'reconcile', 'member'); assert.ok(recovered.request.ticketId); assert.equal(recovered.request.attachmentState, 'pending');
      await store.patchTicketAction(id, 'retry-attachment', 'member'); await waitFor(id, r => r.attachmentState === 'attached'); assert.equal(posts, before); mode = 'ok';
    });
    await t.test('definite rejection allows intentional retry', async () => {
      mode = 'rejected'; const id = await draft({ hostScope: ['tenant:device3'] }); await store.createPatchTicket(id, submit, 'member'); await waitFor(id, r => r.state === 'failed');
      mode = 'ok'; await store.createPatchTicket(id, submit, 'member'); await waitFor(id, r => r.attachmentState === 'attached');
    });
    await t.test('multi-tenant and stale connection drafts cannot send', async () => {
      const before = posts, multi = await draft({ tenantIds: ['a'.repeat(32), 'b'.repeat(32)] });
      await assert.rejects(store.createPatchTicket(multi, submit, 'member'), /multiple CrowdStrike tenants/);
      const id = await draft({ hostScope: ['tenant:device4'] });
      await assert.rejects(store.createPatchTicket(id, { ...submit, connectionRevision: 99 }, 'member'), /connection changed/);
      await db.query("UPDATE dashboard_source_connections SET revision=2 WHERE source='crowdstrike'");
      await assert.rejects(store.createPatchTicket(id, submit, 'member'), /fresh report/); assert.equal(posts, before);
      await db.query("UPDATE dashboard_source_connections SET revision=1 WHERE source='crowdstrike'");
    });
    await t.test('interrupted workers recover, absent lookup never resends', async () => {
      const id = await draft({ hostScope: ['tenant:device5'] });
      await db.query("UPDATE patch_ticket_requests SET state='creating',started_at=now()-interval '4 minutes',cw_target=$2,company_id=30 WHERE id=$1", [id, client.cwTarget(connection)]);
      assert.equal((await store.readPatchTicket(id)).request.state, 'uncertain'); const before = posts;
      await assert.rejects(store.patchTicketAction(id, 'reconcile', 'member'), /No matching ticket/); assert.equal(posts, before);
    });
    await t.test('changing account prevents reading or attaching prior customer tickets', async () => {
      const linked = (await store.listPatchTickets()).requests.find(r => r.ticketId);
      await store.saveCWSettings({ ...connection, companyId: 'other-account' }, 'member');
      await assert.rejects(store.patchTicketAction(linked.id, 'check-status', 'member'), /original ConnectWise account/);
      assert.equal((await store.readCWSettings()).revision, 2);
    });
    await t.test('encoded settings derive the company, omit secrets, preserve blank auth and require re-entry for address changes', async () => {
      const encoded = Buffer.from(`${connection.companyId}+${connection.publicKey}:${connection.privateKey}`).toString('base64');
      const body = { endpoint: connection.endpoint, clientId: connection.clientId, authMode: 'encoded', cwAuth: encoded, companyId: 'ignored-input' };
      const saved = await store.saveCWSettings(body, 'member');
      assert.equal(saved.authMode, 'encoded'); assert.equal(saved.companyId, connection.companyId);
      assert.ok(!JSON.stringify(saved).includes(encoded)); assert.ok(!('cwAuth' in saved)); assert.ok(!('privateKey' in saved));
      await store.saveCWSettings({ ...body, cwAuth: '' }, 'member');
      assert.equal((await store.readCWSettings()).companyId, connection.companyId);
      await assert.rejects(store.saveCWSettings({ ...body, endpoint: 'https://api-eu.myconnectwise.net/v4_6_release/apis/3.0', cwAuth: '' }, 'member'), /CW_AUTH again/);
      await assert.rejects(store.saveCWSettings({ ...body, cwAuth: 'bad-auth' }, 'member'), /valid CW_AUTH/);
      await assert.rejects(store.saveCWSettings({ ...body, cwAuth: 123 }, 'member'), /as text/);
      assert.equal((await store.readCWSettings()).revision, 4);
    });
  } finally { await db.end(); }
});
