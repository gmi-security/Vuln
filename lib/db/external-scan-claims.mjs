/**
 * Durable external-scan reservation primitive. NOT a scheduler or scanner
 * client. Authorization, maintenance window, Nessus completion, and scanner
 * capacity MUST be verified before and after reservation by a future caller.
 * No automatic slot expiry, retry, scan launch or reconciliation is provided.
 */
import { isIP } from 'node:net';

const HEX = /^[a-f0-9]{64}$/;
const DNS_LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;
function exactTarget(value) {
  if (typeof value !== 'string' || !value || value.length > 253 ||
      value !== value.trim() || value !== value.toLowerCase() ||
      value.includes('/') || value.includes('*') || value.endsWith('.')) return false;
  if (isIP(value)) return true;
  return value.split('.').every(part => DNS_LABEL.test(part));
}
const OCCURRENCE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/;

function inputFields(input) {
  if (!input || typeof input !== 'object' || !HEX.test(input.dedupKey ?? ''))
    throw new Error('Invalid external scan dedup key.');
  if (typeof input.companyId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(input.companyId))
    throw new Error('Invalid external scan customer.');
  if (!exactTarget(input.target))
    throw new Error('External scan requires one exact hostname or IP.');
  if (!Number.isSafeInteger(input.nessusScanId) || input.nessusScanId <= 0)
    throw new Error('Invalid Nessus scan identity.');
  if (typeof input.occurrenceAt !== 'string' || !OCCURRENCE.test(input.occurrenceAt) ||
      !Number.isFinite(Date.parse(input.occurrenceAt)))
    throw new Error('Invalid Nessus recurrence timestamp.');
  return [input.dedupKey, input.companyId, input.target, input.nessusScanId, input.occurrenceAt];
}

/**
 * Returns reserved/busy/duplicate. FOR UPDATE NOWAIT provides mutual exclusion,
 * and the slot's persisted claim survives crashes and restarts. Missing schema
 * is an error, not permission to fall back to a process-local queue.
 */
export async function reserveExternalScanClaim(pool, input) {
  const fields = inputFields(input);
  if (!pool?.connect) throw new Error('PostgreSQL pool unavailable.');
  const client = await pool.connect();
  let inTransaction = false;
  try {
    await client.query('BEGIN');
    inTransaction = true;
    await client.query("SET LOCAL lock_timeout = '2s'");
    await client.query("SET LOCAL statement_timeout = '10s'");
    const slot = await client.query('SELECT claim_key FROM public.external_scan_dispatch_slot WHERE slot_id = 1 FOR UPDATE NOWAIT');
    if (slot.rows.length !== 1) throw new Error('External scan slot migration is missing.');
    if (slot.rows[0].claim_key !== null) {
      await client.query('COMMIT');
      inTransaction = false;
      return { state: 'busy' };
    }
    const inserted = await client.query(
      'INSERT INTO public.external_scan_dispatch_claims (claim_key, company_id, target, nessus_scan_id, nessus_occurrence_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (claim_key) DO NOTHING RETURNING claim_key', fields);
    if (inserted.rows.length === 0) {
      await client.query('COMMIT');
      inTransaction = false;
      return { state: 'duplicate' };
    }
    const assigned = await client.query(
      'UPDATE public.external_scan_dispatch_slot SET claim_key = $1, updated_at = now() WHERE slot_id = 1 AND claim_key IS NULL RETURNING claim_key', [fields[0]]);
    if (assigned.rows.length !== 1) throw new Error('External scan slot reservation failed.');
    await client.query('COMMIT');
    inTransaction = false;
    return { state: 'reserved', claimKey: fields[0] };
  } catch (err) {
    if (inTransaction) await client.query('ROLLBACK').catch(() => {});
    if (err?.code === '55P03') return { state: 'busy' };
    throw err;
  } finally {
    client.release();
  }
}

/** Read-only operator view; never releases a claimed slot. */
export async function inspectExternalScanSlot(pool) {
  if (!pool?.query) throw new Error('PostgreSQL pool unavailable.');
  const result = await pool.query('SELECT s.claim_key, s.updated_at AS slot_updated_at, c.company_id, c.target, c.nessus_scan_id, c.nessus_occurrence_at, c.state, c.remote_task_id, c.created_at FROM public.external_scan_dispatch_slot s LEFT JOIN public.external_scan_dispatch_claims c ON c.claim_key = s.claim_key WHERE s.slot_id = 1');
  if (result.rows.length !== 1) throw new Error('External scan slot migration is missing.');
  return result.rows[0];
}
