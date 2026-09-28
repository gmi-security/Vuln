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
const { directSourcesForCustomer, atlasFalconReviewPacket } = module.namespace;

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
