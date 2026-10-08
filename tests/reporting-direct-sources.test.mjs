import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { SourceTextModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const path = resolve('lib/reporting-direct-sources.ts');
const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const module = new SourceTextModule(code, { identifier: path });
await module.link(() => { throw new Error('Unexpected runtime import'); });
await module.evaluate();
const { directSourcesForCustomer, atlasFalconReviewPacket, customerReportingTileIds } = module.namespace;

const dashboard = { canManage: true, storageReady: true, connected: true, crowdstrike: { connected: true },
  queries: [
    { id: 'cve-count', title: 'Unique CVEs', source: 'elastic', result: { rows: [[12]] } },
    { id: 'falcon-open', title: 'Open findings', source: 'crowdstrike', result: { rows: [[80000]] } },
  ] };

test('Atlas keeps both saved Elasticsearch and CrowdStrike results', () => {
  const result = directSourcesForCustomer('CO-147284', dashboard, 'cve-count,falcon-open');
  assert.deepEqual(result.queries.map(query => query.id), ['cve-count', 'falcon-open']);
  assert.deepEqual(result.queries[1].result.rows, [[80000]]);
});

test('non-Atlas and unselected customers receive no saved source results', () => {
  assert.equal(directSourcesForCustomer('CO-2', dashboard, 'cve-count').queries.length, 0);
  assert.equal(directSourcesForCustomer('', dashboard, 'cve-count').queries.length, 0);
  assert.equal(directSourcesForCustomer('CO-147284', dashboard).queries.length, 0);
});

test('Falcon drafts carry Atlas identity only for verified tenant CIDs', () => {
  const packet = atlasFalconReviewPacket({ source: 'crowdstrike', tenantId: 'a'.repeat(32), cves: ['CVE-2026-1234'] }, ['a'.repeat(32)]);
  assert.equal(packet.appCompanyId, 'CO-147284');
  assert.equal(packet.tenantId, 'a'.repeat(32));
  const other = atlasFalconReviewPacket({ source: 'crowdstrike', tenantId: 'b'.repeat(32) }, ['a'.repeat(32)]);
  assert.equal(other.appCompanyId, undefined);
});

test('explicit assignments support multiple customers without sharing cached rows or source metadata',()=>{
  const assignments=JSON.stringify({'CO-147284':['cve-count'],'CO-OTHER':['falcon-open']});
  const all={...dashboard,endpoint:'https://atlas-only.example',crowdstrike:{connected:true,region:'us-1'}};
  const atlas=directSourcesForCustomer('CO-147284',all,'',assignments);
  const other=directSourcesForCustomer('CO-OTHER',all,'',assignments);
  assert.deepEqual(atlas.queries.map(q=>q.id),['cve-count']);assert.equal(atlas.crowdstrike.connected,false);
  assert.deepEqual(other.queries.map(q=>q.id),['falcon-open']);assert.equal(other.connected,false);
  assert.equal(other.endpoint,undefined);assert.equal(other.crowdstrike.region,undefined);
  assert.deepEqual(directSourcesForCustomer('CO-230784',all,'',assignments).queries,[]);
  assert.deepEqual(directSourcesForCustomer('',all,'',assignments).queries,[]);
});

test('ambiguous ownership and malformed configuration fail closed; explicit empty assignment overrides legacy Atlas list',()=>{
  assert.throws(()=>customerReportingTileIds('CO-1','not-json'),/Invalid/);
  assert.throws(()=>customerReportingTileIds('CO-1','[]'),/Invalid/);
  assert.throws(()=>customerReportingTileIds('CO-1',JSON.stringify({'CO-1':['same'],'CO-2':['same']})),/one verified/);
  assert.throws(()=>customerReportingTileIds('CO-1',JSON.stringify({'CO-1':['*']})),/Invalid/);
  assert.deepEqual(customerReportingTileIds('CO-147284','{"CO-147284":[]}','cve-count'),[]);
});

test('disconnected or unavailable sources never turn into fallback global tiles',()=>{
  const disconnected=directSourcesForCustomer('CO-147284',{...dashboard,connected:false},'cve-count,falcon-open');
  assert.deepEqual(disconnected.queries.map(q=>q.id),['falcon-open']);
  const unavailable=directSourcesForCustomer('CO-147284',{...dashboard,storageReady:false},'cve-count');
  assert.equal(unavailable.storageReady,false);assert.deepEqual(unavailable.queries,[]);
});
