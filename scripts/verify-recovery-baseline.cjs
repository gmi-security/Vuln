#!/usr/bin/env node
/* Restore a private baseline into a disposable, socket-only PostgreSQL cluster.
 * Does not load app configuration, run app code, contact providers or start jobs.
 * Requires PostgreSQL 18 server binaries extracted outside the application.
 * Retains the stopped cluster and private logs for inspection. */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

async function main() {
  if (process.platform !== 'linux' || process.getuid() === 0) throw new Error('Run as the unprivileged backup owner on Linux.');
  const [baselineArg, toolsArg] = process.argv.slice(2);
  if (!baselineArg || !toolsArg) throw new Error('Usage: node verify-recovery-baseline.cjs BASELINE_DIRECTORY EXTRACTED_POSTGRES_PREFIX');
  const baseline = fs.realpathSync(baselineArg), prefix = fs.realpathSync(toolsArg);
  const manifest = JSON.parse(fs.readFileSync(path.join(baseline, 'manifest.json'), 'utf8'));
  if (manifest.status !== 'backup-complete-restore-test-pending') throw new Error('A completed baseline is required.');
  process.umask(0o077);
  const dir = fs.mkdtempSync(path.join(baseline, 'restore-'));
  const data = path.join(dir, 'data'), socket = path.join(dir, 'socket');
  fs.mkdirSync(socket, { mode: 0o700 });
  const bin = path.join(prefix, 'usr/lib/postgresql/18/bin');
  const log = fs.openSync(path.join(dir, 'restore.log'), 'wx', 0o600);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PG')));
  Object.assign(env, { PGHOST: socket, PGPORT: '55483', PGUSER: process.env.USER,
    PGDATABASE: 'postgres', PGCONNECT_TIMEOUT: '10', PGAPPNAME: 'vuln2-disposable-restore',
    LD_LIBRARY_PATH: path.join(prefix, 'usr/lib/x86_64-linux-gnu') });
  const result = { startedAt: new Date().toISOString(), status: 'running', directory: dir, databases: [],
    scope: 'Isolated database restore and saved-count comparison; no application, jobs or external actions executed.' };
  const save = () => fs.writeFileSync(path.join(dir, 'verification.json'), JSON.stringify(result, null, 2), { mode: 0o600 });
  save();
  const run = (command, args, capture = false) => new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ['ignore', capture ? 'pipe' : log, log], timeout: 3_600_000 });
    let output = '';
    if (capture) child.stdout.on('data', chunk => { output += chunk; });
    child.once('error', () => reject(new Error(`${path.basename(command)} failed to start; inspect private restore.log.`)));
    child.once('exit', (code, signal) => code === 0 ? resolve(output.trim()) : reject(new Error(`${path.basename(command)} failed (${signal || code}); inspect private restore.log.`)));
  });
  let started = false;
  try {
    await run(path.join(bin, 'initdb'), ['-D', data, '-L', path.join(prefix, 'usr/share/postgresql/18'), '--encoding=UTF8', '--no-locale', '--auth-local=trust', '--auth-host=reject']);
    // Generated paths contain no shell metacharacters; pg_ctl forwards -o to postgres.
    if (!/^[a-zA-Z0-9_/.\-]+$/.test(socket)) throw new Error('Unsupported restore directory characters.');
    await run(path.join(bin, 'pg_ctl'), ['-D', data, '-l', path.join(dir, 'postgresql.log'), '-o',
      `-k ${socket} -h '' -p 55483 -c shared_buffers=128MB -c max_connections=10 -c autovacuum=off`, '-w', 'start']);
    started = true;
    console.log(JSON.stringify({ event: 'isolated-restore-started', directory: dir }));
    for (const entry of manifest.databases.filter(value => value.file)) {
      if (!/^[a-z]+\.dump$/.test(entry.file)) throw new Error('Invalid dump filename.');
      const dump = path.join(baseline, entry.file);
      const digest = crypto.createHash('sha256');
      for await (const chunk of fs.createReadStream(dump)) digest.update(chunk);
      if (digest.digest('hex') !== entry.sha256) throw new Error('Dump checksum mismatch.');
      const name = `recovery_${entry.role}`;
      if (!/^[a-z_]+$/.test(name)) throw new Error('Invalid restore role.');
      await run('/usr/lib/postgresql/18/bin/createdb', [name]);
      await run('/usr/bin/nice', ['-n', '10', '/usr/lib/postgresql/18/bin/pg_restore', '--exit-on-error', '--no-owner', '--no-privileges', '--dbname', name, dump]);
      const check = { role: entry.role, counts: {}, matched: true };
      for (const [table, expected] of Object.entries(entry.counts)) {
        if (!/^[a-z_]+$/.test(table)) throw new Error('Invalid verification table.');
        const actual = await run('/usr/lib/postgresql/18/bin/psql', ['-X', '-At', '--dbname', name, '--command', `SELECT count(*) FROM public.${table}`], true);
        check.counts[table] = { expected, actual };
        if (actual !== expected) check.matched = false;
      }
      const invalidIndexes = await run('/usr/lib/postgresql/18/bin/psql', ['-X', '-At', '--dbname', name, '--command', 'SELECT count(*) FROM pg_index WHERE NOT indisvalid'], true);
      check.invalidIndexes = Number(invalidIndexes);
      result.databases.push(check); save();
      if (!check.matched || check.invalidIndexes !== 0) throw new Error('Restored database verification failed.');
      console.log(JSON.stringify({ event: 'database-restored-and-verified', role: entry.role }));
    }
    result.status = 'verified';
  } catch (error) {
    result.status = 'failed';
    throw error;
  } finally {
    if (started) {
      try {
        await run(path.join(bin, 'pg_ctl'), ['-D', data, '-m', 'fast', '-w', 'stop']);
        result.clusterStopped = true;
      } catch (error) { result.clusterStopped = false; result.status = 'failed'; throw error; }
      finally { result.finishedAt = new Date().toISOString(); save(); fs.closeSync(log); }
    } else { result.finishedAt = new Date().toISOString(); save(); fs.closeSync(log); }
  }
  console.log(JSON.stringify({ event: 'restore-verification-complete', status: result.status, directory: dir }));
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
