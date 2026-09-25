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
  const cache = new Map();
  async function load(path) {
    path = resolve(path);
    if (cache.has(path)) return cache.get(path);
    const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    const mod = new SourceTextModule(code, { identifier: path }); cache.set(path, mod);
    await mod.link(async name => {
      if (overrides[name]) { const values = overrides[name]; return new SyntheticModule(Object.keys(values), function() { for (const key of Object.keys(values)) this.setExport(key, values[key]); }); }
      if (name.startsWith('.')) return load(resolve(dirname(path), `${name}.ts`));
      const values = await import(name); return new SyntheticModule(Object.keys(values), function() { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
    });
    return mod;
  }
  return async path => { const mod = await load(path); await mod.evaluate(); return mod.namespace; };
}
const connection = { endpoint: 'https://api-na.myconnectwise.net/v4_6_release/apis/3.0', companyId: 'test-company', clientId: 'test-client', publicKey: 'test-public', privateKey: 'test-private+/=' };
const originalSecret = process.env.NEXTAUTH_SECRET;
process.env.NEXTAUTH_SECRET = 'local-connectwise-test-secret-only-123456789';
test.after(() => { if (originalSecret === undefined) delete process.env.NEXTAUTH_SECRET; else process.env.NEXTAUTH_SECRET = originalSecret; });
let replies = [], calls = [], resolvedAddress = '8.8.8.8';
const client = await loader({
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
})('lib/connectwise-client.ts');

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
test('routing validates BoardInfo without reading board setup or attempting ticket creation', async () => {
  calls = []; replies = [{ body: { id: 10, name: 'Patch board' } }, { body: { id: 11, name: 'Ready' } }, { body: { id: 12, name: 'High' } }];
  const labels = await client.validateCWRouting(connection, { boardId: 10, statusId: 11, priorityId: 12 });
  assert.equal(labels.board.name, 'Patch board');
  assert.deepEqual(calls.map(c => c.url.pathname.replace('/v4_6_release/apis/3.0', '')), ['/service/info/boards/10', '/service/boards/10/statuses/11', '/service/priorities/12']);
  assert.ok(calls.every(c => c.options.method === 'GET'));
  calls = []; replies = [{ status: 403, body: { message: 'You do not have security permission to perform this action.' } }];
  await assert.rejects(client.cwOptions(connection, 'boards'), /HTTP 403/);
  assert.equal(calls.length, 1, 'No fallback to the more privileged setup endpoint and no trial ticket');
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
  const tickets = new Map();
  const store = await loader({
    './elastic-dashboard-store': { dashboardDatabase: async () => db },
    './connectwise-client': { ...client,
      cwOptions: async () => ({ options: [{ id: 10, name: 'Customer patching' }], more: false, page: 1 }),
      validateCWRouting: async (_c, r) => ({ company: { id: r.companyId, name: 'Actual customer' }, board: { id: r.boardId, name: 'Customer patching' } }),
      cwRequest: async (_c, path, method, body) => {
        if (method === 'POST') { posts++; if (pausePost) await pausePost;
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
  const submit = { title: 'Patch CVE', body: packet.body, connectionRevision: 1, routing: { companyId: 30, boardId: 10, statusId: 11, priorityId: 12 } };
  async function waitFor(id, predicate) { for (let i = 0; i < 200; i++) { const { request } = await store.readPatchTicket(id); if (predicate(request)) { await new Promise(r => setTimeout(r, 20)); return request; } await new Promise(r => setTimeout(r, 10)); } assert.fail('Worker did not reach expected state'); }
  try {
    await store.saveCWSettings(connection, 'admin@example.test');
    const settings = await store.readCWSettings(); assert.equal(settings.revision, 1); assert.ok(!JSON.stringify(settings).includes('test-private')); assert.ok(!('publicKey' in settings));
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
