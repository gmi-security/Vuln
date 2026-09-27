import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { SourceTextModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

async function load(path) {
  const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const module = new SourceTextModule(code, { identifier: path });
  await module.link(() => { throw new Error('Unexpected runtime import'); });
  await module.evaluate();
  return module.namespace;
}

const { exactCompanyMatch } = await load(resolve('lib/reporting-company-match.ts'));
const { patchReviewRows } = await load(resolve('lib/patch-review-rows.ts'));

test('automatic linking only accepts a unique exact customer name', () => {
  const companies = [{ id: 'atlas', name: 'Atlas Healthcare' }, { id: 'other', name: 'Atlas Healthcare East' }];
  assert.equal(exactCompanyMatch('  ATLAS   HEALTHCARE ', companies)?.id, 'atlas');
  assert.equal(exactCompanyMatch('Atlas', companies), null);
  assert.equal(exactCompanyMatch('Atlas Healthcare', [...companies, { id: 'duplicate', name: 'atlas healthcare' }]), null);
});

test('existing saved reports recover asset detail from CSV, including quoted cells', () => {
  const rows = patchReviewRows({ csv: '\uFEFF"cve","asset","severity","risk_score","connectors","finding_id","remediation"\r\n"CVE-2026-1234","host, one","High","72","nessus; vulners","finding-1","Apply ""vendor"" patch"\r\n', deviceCves: [] });
  assert.equal(rows.length, 1);
  assert.deepEqual([rows[0].asset, rows[0].cve, rows[0].severity, rows[0].risk, rows[0].connectors, rows[0].findingId],
    ['host, one', 'CVE-2026-1234', 'High', 72, ['nessus', 'vulners'], 'finding-1']);
});
