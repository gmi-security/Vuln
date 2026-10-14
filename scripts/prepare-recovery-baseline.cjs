#!/usr/bin/env node
/* Explicit operator tool. Never imported by the application or run on startup.
 * Reads production; writes only a private backup directory. No app restart,
 * schema initialization, database restore or external service actions. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');
const { spawn, execFileSync } = require('node:child_process');

async function main() {
  if (process.platform !== 'linux') throw new Error('Run this backup tool on the Linux application server.');
  const [appArg, parentArg] = process.argv.slice(2);
  if (!appArg || !parentArg) throw new Error('Usage: node prepare-recovery-baseline.cjs APP_DIRECTORY PRIVATE_BACKUP_PARENT');
  const app = fs.realpathSync(appArg);
  process.umask(0o077);
  fs.mkdirSync(path.resolve(parentArg), { recursive: true, mode: 0o700 });
  const parent = fs.realpathSync(parentArg);
  if (parent === app || parent.startsWith(app + path.sep)) throw new Error('Backups must be outside the application directory.');
  const dir = fs.mkdtempSync(path.join(parent, 'baseline-'));
  const log = fs.openSync(path.join(dir, 'backup.log'), 'wx', 0o600);
  const manifest = { version: 1, startedAt: new Date().toISOString(), app, status: 'running', databases: [], limitations: [
    'Online backup: subsequent production writes and external ticket actions are not part of this recovery point.',
    'Runtime PM2 environment and root-owned PM2 configuration have not been exported.',
    'Archive readability checks are not a full restore test. Restore verification is a separate step.',
    'Filesystem archive is an online copy, not an atomic filesystem snapshot. Preserve application/database compatibility before recovery.',
  ] };
  const writeManifest = () => fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2), { mode: 0o600 });
  writeManifest();
  console.log(JSON.stringify({ event: 'backup-started', directory: dir }));
  const run = (command, args, options = {}) => new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', log, log], timeout: 3_600_000, ...options });
    child.once('error', () => reject(new Error(`${path.basename(command)} could not start; inspect private backup.log.`)));
    child.once('exit', (code, signal) => code === 0 ? resolve() : reject(new Error(`${path.basename(command)} failed (${signal || code}); inspect private backup.log.`)));
  });
  async function digest(file) {
    const hash = crypto.createHash('sha256');
    for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
    return hash.digest('hex');
  }
  try {
    manifest.commit = execFileSync('git', ['-c', `safe.directory=${app}`, '-C', app, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    manifest.localChanges = execFileSync('git', ['-c', `safe.directory=${app}`, '-C', app, 'status', '--porcelain'], { encoding: 'utf8' }).trim().split('\n').filter(Boolean);
    const buildId = path.join(app, '.next', 'BUILD_ID');
    manifest.buildId = fs.existsSync(buildId) ? fs.readFileSync(buildId, 'utf8').trim() : null;
    manifest.nodeVersion = process.version;
    manifest.dumpVersion = execFileSync('pg_dump', ['--version'], { encoding: 'utf8' }).trim();
    const archive = path.join(dir, 'application.tar.gz');
    await run('tar', ['--acls', '--xattrs', '--exclude=./.next/cache', '-czf', archive, '-C', app, '.']);
    await run('tar', ['-tzf', archive]);
    manifest.application = { file: path.basename(archive), bytes: fs.statSync(archive).size, sha256: await digest(archive) };
    writeManifest();
    console.log(JSON.stringify({ event: 'application-archived', bytes: manifest.application.bytes }));
    const req = createRequire(path.join(app, 'package.json'));
    req('@next/env').loadEnvConfig(app, false, { info() {}, warn() {}, error() {} });
    const { Client } = req('pg');
    const seen = new Map();
    const configs = [['application', process.env.DATABASE_URL], ['dashboard', process.env.ELASTIC_VULN_DATABASE_URL || process.env.DATABASE_URL]];
    for (const [role, value] of configs) {
      if (!value) throw new Error(`Missing ${role} database configuration.`);
      const url = new URL(value);
      const target = `${url.hostname}:${url.port || 5432}${url.pathname}`;
      if (seen.has(target)) { manifest.databases.push({ role, sameTargetAs: seen.get(target) }); continue; }
      seen.set(target, role);
      const record = { role, status: 'running', counts: {} }; manifest.databases.push(record); writeManifest();
      const client = new Client({ connectionString: value, ssl: { rejectUnauthorized: false }, connectionTimeoutMillis: 15000,
        application_name: 'vuln2-recovery-baseline', options: '-c default_transaction_read_only=on -c statement_timeout=30000' });
      try {
        await client.connect();
        await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
        const snapshot = (await client.query('SELECT pg_export_snapshot() AS snapshot')).rows[0].snapshot;
        record.serverVersion = (await client.query('SHOW server_version')).rows[0].server_version;
        record.snapshotAt = (await client.query('SELECT now() AS time')).rows[0].time;
        const tables = new Set((await client.query("SELECT tablename FROM pg_tables WHERE schemaname='public'")).rows.map(r => r.tablename));
        for (const table of ['vuln_store', 'defender_connections', 'elastic_dashboard_queries', 'patch_ticket_requests', 'patch_group_ticket_requests', 'patch_customer_routing', 'cve_enrichment']) {
          if (tables.has(table)) record.counts[table] = (await client.query(`SELECT count(*)::text AS count FROM public.${table}`)).rows[0].count;
        }
        record.extensions = (await client.query('SELECT extname,extversion FROM pg_extension ORDER BY extname')).rows;
        const dump = path.join(dir, `${role}.dump`);
        // Credentials are child environment variables, never command-line args or public output.
        const env = { ...process.env, PGHOST: url.hostname, PGPORT: url.port || '5432', PGDATABASE: decodeURIComponent(url.pathname.slice(1)),
          PGUSER: decodeURIComponent(url.username), PGPASSWORD: decodeURIComponent(url.password), PGSSLMODE: 'require', PGCONNECT_TIMEOUT: '15',
          PGAPPNAME: 'vuln2-recovery-dump', PGOPTIONS: '-c default_transaction_read_only=on -c statement_timeout=3600000' };
        console.log(JSON.stringify({ event: 'database-dump-started', role }));
        await run('pg_dump', ['--format=custom', '--compress=1', '--lock-wait-timeout=15s', `--snapshot=${snapshot}`, '--file', dump], { env });
        await client.query('COMMIT');
        await run('pg_restore', ['--list', dump]);
        await run('pg_restore', ['--file=/dev/null', dump]);
        record.file = path.basename(dump); record.bytes = fs.statSync(dump).size; record.sha256 = await digest(dump); record.status = 'archive-verified';
      } finally { await client.end().catch(() => {}); }
      writeManifest(); console.log(JSON.stringify({ event: 'database-archived', role, bytes: record.bytes }));
    }
    manifest.status = 'backup-complete-restore-test-pending';
    manifest.finishedAt = new Date().toISOString(); writeManifest();
    console.log(JSON.stringify({ event: 'backup-complete', directory: dir, status: manifest.status }));
  } catch (error) {
    manifest.status = 'failed'; manifest.error = error.code || 'BACKUP_STEP_FAILED'; writeManifest();
    throw error;
  } finally { fs.closeSync(log); }
}
main().catch(error => { console.error('Backup stopped:', error.message?.includes('private backup.log') ? error.message : error.code || 'Inspect the private manifest/log.'); process.exitCode = 1; });
