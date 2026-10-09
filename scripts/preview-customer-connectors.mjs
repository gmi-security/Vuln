// Read-only. Run with Node --experimental-vm-modules. No schema or vendor calls.
// Optional --env-file /absolute/path/.env.local uses Next's existing env loader.
// Output contains customer/tenant IDs: keep it private, outside the web root.
import { writeFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import pg from 'pg';
import nextEnv from '@next/env';
import { loadConnectorPreview } from './connector-preview-loader.mjs';
import { readApplicationConnectorMetadata, readDashboardConnectorMetadata } from '../lib/db/connector-metadata.mjs';

const args = process.argv.slice(2);
let output, envFile;
for (let n = 0; n < args.length; n += 2) {
  if (!args[n + 1] || !['--output', '--env-file'].includes(args[n])) throw new Error('Use --output PATH [--env-file PATH].');
  if (args[n] === '--output') output = resolve(args[n + 1]);
  else envFile = resolve(args[n + 1]);
}
if (!output) throw new Error('A private --output path is required. Existing files are never overwritten.');
const clients = [];
let stage = 'environment';
const deadline = setTimeout(() => { console.error('Connector preview exceeded two minutes; no usable report.'); process.exit(1); }, 120000);
try {
  if (envFile) {
    // The loader honors existing environment overrides, as in the application.
    // Its logger is suppressed so a malformed line cannot echo credentials.
    nextEnv.processEnv([{ path: envFile, contents: await readFile(envFile, 'utf8'), env: {} }], undefined,
      { info() {}, error() {} }, true);
  }
  const env = { ...process.env };
  if (!env.DATABASE_URL) throw new Error('Application database is not configured.');
  async function connect(url) {
    const client = new pg.Client({ connectionString: url, application_name: 'vuln2-connector-preview',
      options: '-c default_transaction_read_only=on', statement_timeout: 15000, connectionTimeoutMillis: 5000 });
    clients.push(client); await client.connect(); return client;
  }
  stage = 'application-connect';
  const app = await connect(env.DATABASE_URL);
  stage = 'application-metadata';
  const application = await readApplicationConnectorMetadata(app);
  stage = 'dashboard-connect';
  const dashboard = env.ELASTIC_VULN_DATABASE_URL && env.ELASTIC_VULN_DATABASE_URL !== env.DATABASE_URL
    ? await connect(env.ELASTIC_VULN_DATABASE_URL) : app;
  stage = 'dashboard-metadata';
  const saved = await readDashboardConnectorMetadata(dashboard);
  stage = 'preview-validation';
  const build = await loadConnectorPreview();
  const preview = build({ ...application, ...saved }, env);
  const report = { collectedAt: new Date().toISOString(),
    environment: envFile ? 'file-plus-process-overrides' : 'process-environment',
    consistency: 'separate-read-only-snapshots; recollect-before-import',
    coverage: { application: application.coverage, dashboard: saved.coverage }, ...preview };
  stage = 'private-file-write';
  await writeFile(output, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ companies: preview.companies.length, candidates: preview.candidates.length,
    bindingsEnabled: 0, mode: preview.mode, fingerprint: preview.fingerprint }));
} catch (error) {
  // Database/parser error messages can include URLs, SQL values or credentials.
  const code = typeof error?.code === 'string' && /^[0-9A-Z]{5}$/.test(error.code) ? error.code : 'not-reported';
  const safeMessages = new Set(['Connector metadata limit exceeded; no partial preview produced.',
    'Invalid saved company metadata.', 'Invalid companies in snapshot metadata.', 'Invalid company snapshot bucket.',
    'Invalid legacy companies.', 'Invalid saved tile owner.', 'Invalid customer reporting tile assignments.',
    'Each reporting tile must have one verified customer owner.',
    'Duplicate company IDs in source metadata; review cannot continue.', 'Duplicate connector evidence; review cannot continue.']);
  const detail = safeMessages.has(error?.message) ? ` ${error.message}` : '';
  console.error(`Connector preview failed at ${stage} (code ${code}). No complete report produced.${detail} Check access, metadata/schema and mapping configuration.`);
  process.exitCode = 1;
} finally {
  await Promise.allSettled(clients.map(client => client.end()));
  clearTimeout(deadline);
}
