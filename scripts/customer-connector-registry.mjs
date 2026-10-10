// Operator-only registry workflow. Never imports the application runtime,
// initializes schema, decrypts credentials or calls a provider API.
import { readFile, open, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { userInfo, hostname } from 'node:os';
import { pathToFileURL } from 'node:url';
import pg from 'pg';
import nextEnv from '@next/env';
import { loadConnectorPreview, loadConnectorDraftStore, loadConnectorBindingStore, loadInventoryRouting, loadSpotlightRouting } from './connector-preview-loader.mjs';
import { readApplicationConnectorMetadata, readDashboardConnectorMetadata } from '../lib/db/connector-metadata.mjs';

const commands = {
  import: ['--fingerprint', '--env-file'],
  export: ['--company', '--output', '--env-file'],
  review: ['--input', '--env-file'],
  assign: ['--input', '--env-file'],
  'export-bindings': ['--company', '--output', '--env-file'],
  'route-spotlight': ['--input', '--env-file'],
  'export-spotlight-routes': ['--company', '--output', '--env-file'],
  'route-inventory': ['--input', '--env-file'],
  'export-inventory-routes': ['--company', '--output', '--env-file'],
};
export function parseRegistryArgs(args) {
  const [command, ...rest] = args;
  if (!commands[command] || rest.length % 2) throw new Error('Use import, export or review with named options.');
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    const [key, value] = rest.slice(i, i + 2);
    if (!commands[command].includes(key) || key in options || !value || value.startsWith('--')) throw new Error('Invalid or duplicate command option.');
    options[key] = value;
  }
  if (command === 'import' && !/^[a-f0-9]{64}$/.test(options['--fingerprint'] ?? '')) throw new Error('A reviewed preview fingerprint is required.');
  if (command.startsWith('export') && (!options['--company'] || options['--company'].length > 100 || !options['--output'])) throw new Error('Export requires a customer and private output path.');
  if (['review','assign','route-inventory','route-spotlight'].includes(command) && !options['--input']) throw new Error('Review requires a private input file.');
  return { command, options };
}
export function registryReviewInput(value) {
  const keys = ['id', 'expectedRevision', 'candidateHash', 'decision', 'proposal', 'note'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length ||
      Object.keys(value).some(key => !keys.includes(key))) throw new Error('Review file must contain exactly one review request, without credentials or actor fields.');
  return value;
}
export function exportRegistryDrafts(companyId, rows) {
  return {
    companyId, mode: 'inactive-proposals', exportedAt: new Date().toISOString(),
    instruction: 'Copy one reviewRequest into a separate private JSON file. Verify scope, choose a decision and add a non-secret note. Reviewed proposals remain inactive.',
    drafts: rows.map(row => ({
      provider: row.candidate.provider, connectionRef: row.candidate.connectionRef,
      evidence: row.candidate.evidence, capabilities: row.candidate.capabilities,
      configured: row.candidate.configured, sourcePresent: row.source_present,
      reasons: row.candidate.review, reviewState: row.review_state, enabled: false,
      reviewRequest: { id: row.id, expectedRevision: row.revision, candidateHash: row.candidate_hash,
        decision: 'save-draft', proposal: { ...row.proposal, companyId: row.proposal.companyId ?? companyId }, note: '' },
    })),
  };
}

export async function runRegistry(args, runtimeEnv = process.env) {
  const { command, options } = parseRegistryArgs(args);
  const clients = [];
  let pool, file;
  try {
    if (options['--env-file']) {
      const path = resolve(options['--env-file']);
      nextEnv.processEnv([{ path, contents: await readFile(path, 'utf8'), env: {} }], undefined, { info() {}, error() {} }, true);
    }
    const env = { ...runtimeEnv };
    if (!env.DATABASE_URL) throw new Error('Application database is not configured.');
    const actor = `operator:${userInfo().username}@${hostname()}`;
    // Export is read-only at the connection level, including list queries.
    const poolOptions = { connectionString: env.DATABASE_URL, max: 2, connectionTimeoutMillis: 5000,
      statement_timeout: 15000, application_name: 'vuln2-connector-registry',
      ...(command.startsWith('export') ? { options: '-c default_transaction_read_only=on' } : {}) };
    pool = new pg.Pool(poolOptions);
    pool.on('error', () => {}); // Caller reports a redacted failure, never a raw connection URL.
    async function metadataClient(url) {
      const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 5000, statement_timeout: 15000,
        options: '-c default_transaction_read_only=on', application_name: 'vuln2-connector-registry-metadata' });
      clients.push(client);
      client.on('error', () => {});
      await client.connect();
      return client;
    }
    const app = await metadataClient(env.DATABASE_URL);
    const operationalCommand = ['route-inventory','export-inventory-routes','route-spotlight','export-spotlight-routes'].includes(command);
    const dashboard = !operationalCommand && env.ELASTIC_VULN_DATABASE_URL && env.ELASTIC_VULN_DATABASE_URL !== env.DATABASE_URL
      ? await metadataClient(env.ELASTIC_VULN_DATABASE_URL) : app;
    const build = await loadConnectorPreview(), store = (await loadConnectorDraftStore())(pool);
    const collect = async () => build({ ...await readApplicationConnectorMetadata(app),
      ...(operationalCommand ? { connections: [], tiles: [] } : await readDashboardConnectorMetadata(dashboard)) }, env);
    if (command === 'import') return { action: command, ...await store.importPreview(options['--fingerprint'], actor, collect), enabledBindings: 0 };
    if (['review','assign','route-inventory','route-spotlight'].includes(command)) {
      const path = resolve(options['--input']);
      if ((await stat(path)).size > 32 * 1024) throw new Error('Review file exceeds 32 KiB.');
      const value = JSON.parse(await readFile(path, 'utf8'));
      if (command === 'route-spotlight') return { action: command,
        ...await (await loadSpotlightRouting()).createSpotlightRoutingStore(pool).save(value,actor,collect) };
      if (command === 'route-inventory') return { action: command,
        ...await (await loadInventoryRouting()).createInventoryRoutingStore(pool).save(value,actor,collect) };
      const result = command === 'assign'
        ? await (await loadConnectorBindingStore())(pool).save(value,actor,collect)
        : await store.reviewCurrentDraft(registryReviewInput(value), actor, collect);
      return { action: command, revision: result.revision, reviewState: result.reviewState ?? result.review_state, enabledBindings: 0 };
    }
    if (command === 'export-spotlight-routes') {
      const result = await (await loadSpotlightRouting()).createSpotlightRoutingStore(pool).exportCustomer(options['--company']);
      file = await open(resolve(options['--output']),'wx',0o600);
      await file.writeFile(JSON.stringify(result,null,2)+'\n');
      return { action:command, routes:result.routes.length };
    }
    if (command === 'export-inventory-routes') {
      const result = await (await loadInventoryRouting()).createInventoryRoutingStore(pool).exportCustomer(options['--company']);
      file = await open(resolve(options['--output']),'wx',0o600);
      await file.writeFile(JSON.stringify(result,null,2)+'\n');
      return { action:command, routes:result.routes.length };
    }
    if(command === 'export-bindings') {
      const result = await (await loadConnectorBindingStore())(pool).list(options['--company'],collect);
      file = await open(resolve(options['--output']),'wx',0o600);
      await file.writeFile(JSON.stringify(result,null,2)+'\n');
      return { action:command, bindings:result.items.length, enabledBindings:0 };
    }
    const preview = await collect();
    if (!preview.companies.some(c => c.id === options['--company'])) throw new Error('Choose an existing non-demo customer.');
    const rows = await store.listCustomerDrafts(options['--company'], true);
    // wx prevents accidentally overwriting a prior operator decision or symlink.
    file = await open(resolve(options['--output']), 'wx', 0o600);
    await file.writeFile(JSON.stringify(exportRegistryDrafts(options['--company'], rows), null, 2) + '\n');
    return { action: command, drafts: rows.length, enabledBindings: 0 };
  } finally {
    await file?.close();
    await Promise.allSettled(clients.map(client => client.end()));
    await pool?.end();
  }
}

const safeMessages = new Set([
  'Use import, export or review with named options.', 'Invalid or duplicate command option.',
  'A reviewed preview fingerprint is required.', 'Export requires a customer and private output path.',
  'Review requires a private input file.', 'Application database is not configured.',
  'Review file exceeds 32 KiB.', 'Review file must contain exactly one review request, without credentials or actor fields.',
  'Source metadata changed; collect and review a new preview.', 'Source metadata changed; import a fresh preview before reviewing.',
  'Draft changed; reload before reviewing.', 'Choose an existing non-demo customer.',
  'Resolve source configuration conflicts before review.', 'Only present configured connections can be reviewed as bindings.',
  'Resolve existing customer ownership before review.', 'Resolve the saved tenant mapping before review.',
  'Choose authority supported by this source capability.', 'Record the verified tenant, dataset or targets before review.',
  'Vendor tenant verification is required.', 'Elasticsearch dataset verification is required.',
  'Approved scanner targets are required.', 'Decision and review note required.', 'Unexpected registry fields.',
  'Unexpected binding fields.', 'Binding customer cannot be changed.', 'This source belongs to a different customer.',
  'Binding changed; export current assignments before reviewing.', 'Historical data cannot be assigned as a connection.',
  'Valid customer and source evidence are required.', 'Valid binding revision required.', 'Invalid binding decision.',
  'A non-secret binding review note is required.', 'Customer binding limit exceeded.',
  'Invalid spotlight routing approval.', 'Spotlight routing changed; export current state before approval.',
  'No spotlight route exists to disable.', 'Spotlight binding changed; review current state before approval.',
  'Spotlight assignment needs a current review.', 'Spotlight requires a primary findings assignment for one configured Falcon connection.',
  'Spotlight routing limit exceeded.',
  'Invalid inventory routing approval.', 'Inventory routing changed; export current state before approval.',
  'No inventory route exists to disable.', 'Inventory binding changed; review current state before approval.',
  'Inventory assignment needs a current review.', 'This assignment is not supported by the inventory import router.',
  'Automate routing requires its numeric client ID.', 'Intune routing requires the configured tenant ID.',
  'Tidal routing requires its exact company ID.', 'CrowdStrike routing requires the 32-character CID.',
  'Inventory routing limit exceeded.', 'Choose an existing customer.',
]);
export function registryFailure(error) {
  if (safeMessages.has(error?.message)) return error.message;
  if (error?.code === '42P01') return 'Registry tables are not installed. Review the explicit migration; this command does not create tables.';
  if (error?.code === 'EEXIST') return 'Output already exists. Choose a new private output file.';
  if (error?.code === '23505') return 'A conflicting approval already exists. Export current state and resolve source ownership before retrying.';
  return 'Registry operation failed. No success is confirmed. Check database access, input and operator logs; recollect before retrying.';
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const deadline = setTimeout(() => { console.error('Registry operation exceeded two minutes. Outcome is unconfirmed; inspect the registry before retrying.'); process.exit(1); }, 120000);
  try { console.log(JSON.stringify(await runRegistry(process.argv.slice(2)))); }
  catch (error) { console.error(registryFailure(error)); process.exitCode = 1; }
  finally { clearTimeout(deadline); }
}
