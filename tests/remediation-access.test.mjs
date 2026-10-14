import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import ts from 'typescript';

const synthetic = values => new SyntheticModule(Object.keys(values), function () {
  for (const [key, value] of Object.entries(values)) this.setExport(key, value);
});

async function harness({ enabled = true, elastic = true, accessError, canManage = false } = {}) {
  const calls = [];
  class DashboardError extends Error { constructor(message, status) { super(message); this.status = status; } }
  const stubs = {
    'next/navigation': { notFound: () => { throw new Error('NOT_FOUND'); }, redirect: url => { throw new Error(`REDIRECT:${url}`); } },
    '@/components/CustomerReportingPage': { default: 'CustomerReportingPage' },
    '@/lib/elastic-dashboard-http': { dashboardAccess: async () => {
      calls.push('access');
      if (accessError) throw new DashboardError('access error', accessError);
      return { canManage };
    } },
    '@/lib/elastic-dashboard': { DashboardError },
    '@/lib/elastic-vuln-server': { elasticVulnEnabled: () => elastic },
    '@/lib/remediation-server': { remediationUiEnabled: () => enabled },
    'react/jsx-runtime': { jsx: (type, props) => ({ type, props }) },
  };
  const modules = new Map();
  async function load(file) {
    if (modules.has(file)) return modules.get(file);
    if (stubs[file]) { const stub = synthetic(stubs[file]); modules.set(file, stub); return stub; }
    const path = file === '@/lib/remediation-view' ? 'lib/remediation-view.ts' : file;
    const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: {
      target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX,
    } }).outputText;
    const module = new SourceTextModule(code);
    modules.set(file, module);
    await module.link(load);
    return module;
  }
  const page = await load('app/remediation/page.tsx'); await page.evaluate();
  return { render: query => page.namespace.default({ searchParams: Promise.resolve(query) }), calls };
}

test('disabled rollout cannot expose the new page or invoke reporting services', async () => {
  for (const options of [{ enabled: false }, { elastic: false }]) {
    const h = await harness(options);
    await assert.rejects(h.render({ companyId: 'CO-230784' }), /NOT_FOUND/);
    assert.deepEqual(h.calls, []);
  }
});

test('new route retains the existing login and permission enforcement', async () => {
  const loggedOut = await harness({ accessError: 401 });
  await assert.rejects(loggedOut.render({}), /REDIRECT:\/login/);
  const forbidden = await harness({ accessError: 403 });
  await assert.rejects(forbidden.render({}), error => error.status === 403);
  const reader = await harness({ canManage: false });
  const page = await reader.render({ companyId: 'CO-230784', view: 'tickets' });
  assert.equal(page.props.canManage, false);
  assert.equal(page.props.initialCompanyId, 'CO-230784');
  assert.equal(page.props.initialView, 'tickets');
});

test('missing selection remains empty and an unknown view cannot select a global dashboard', async () => {
  const h = await harness();
  const page = await h.render({ view: 'global' });
  assert.equal(page.props.initialCompanyId, '');
  assert.equal(page.props.initialView, 'overview');
});
