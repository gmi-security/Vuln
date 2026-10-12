import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import ts from 'typescript';

async function harness() {
  const calls = [];
  class DashboardError extends Error { constructor(message, status) { super(message); this.status = status; } }
  const values = {
    './elastic-dashboard': { DashboardError },
    './store': {
      ensureHydrated: async () => { calls.push('hydrate'); },
      getCompany: id => {
        calls.push(id);
        return ({ CLIENT: { id: 'CLIENT', kind: 'client' }, INTERNAL: { id: 'INTERNAL', kind: 'internal' },
          DEMO: { id: 'DEMO', isDemo: true }, WRONG: { id: 'OTHER' } })[id];
      },
    },
  };
  const code = ts.transpileModule(await readFile('lib/customer-scope.ts', 'utf8'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText;
  const module = new SourceTextModule(code);
  await module.link(name => new SyntheticModule(Object.keys(values[name]), function () {
    for (const [key, value] of Object.entries(values[name])) this.setExport(key, value);
  }));
  await module.evaluate();
  return { resolve: module.namespace.resolveCustomerScope, calls };
}

test('customer scope never falls back to an unselected or malformed global read', async () => {
  const h = await harness();
  for (const value of ['', undefined, null, 123, {}, 'x'.repeat(101)]) {
    await assert.rejects(h.resolve(value), error => error.status === 400);
  }
  assert.deepEqual(h.calls, []);
});

test('unknown, demo or mismatched identities cannot become a customer scope', async () => {
  const h = await harness();
  for (const value of ['MISSING', 'DEMO', 'WRONG']) {
    await assert.rejects(h.resolve(value), error => error.status === 404);
  }
});

test('client and internal company IDs remain usable without changing permissions', async () => {
  const h = await harness();
  for (const id of ['CLIENT', 'INTERNAL']) {
    const scope = await h.resolve(id);
    assert.equal(scope.companyId, id);
    assert.equal(scope.company.id, id);
    assert.equal(Object.isFrozen(scope), true);
  }
  assert.deepEqual(h.calls, ['hydrate', 'CLIENT', 'hydrate', 'INTERNAL']);
});
