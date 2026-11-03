/**
 * Recovery bookkeeping for external scan dispatch. Does not create/start a
 * remote scan or release the global slot. Missing DB schema and uncertain
 * operations fail closed: the claim stays reserved until verified.
 */
const CLAIM = /^[0-9a-f]{64}$/;
const TASK = /^[A-Za-z0-9_-]{1,128}$/;

async function withClaimLock(pool, claimKey, action) {
  if (!CLAIM.test(claimKey ?? '') || !pool?.connect) throw Error('Invalid claim or database connection.');
  const client = await pool.connect();
  let begun = false;
  try {
    await client.query('BEGIN'); begun = true;
    await client.query("SET LOCAL lock_timeout='2s'");
    await client.query("SET LOCAL statement_timeout='10s'");
    const slot = await client.query(
      'SELECT claim_key FROM public.external_scan_dispatch_slot WHERE slot_id=1 FOR UPDATE NOWAIT'
    );
    if (slot.rows.length !== 1 || slot.rows[0].claim_key !== claimKey) {
      throw Error('Claim is not the current globally reserved scan.');
    }
    const found = await client.query(
      'SELECT claim_key, state, remote_task_id FROM public.external_scan_dispatch_claims WHERE claim_key=$1 FOR UPDATE',
      [claimKey],
    );
    if (found.rows.length !== 1) throw Error('Reserved claim record is missing.');
    const result = await action(client, found.rows[0]);
    await client.query('COMMIT'); begun = false;
    return result;
  } catch (e) {
    if (begun) await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally { client.release(); }
}

/**
 * Persist the first confirmed Greenbone task ID. Repeated identical IDs are
 * idempotent. A different ID or a reconciled/terminal claim cannot overwrite.
 */
export async function recordExternalScanRemoteTask(pool, claimKey, taskId) {
  if (!TASK.test(taskId ?? '')) throw Error('Invalid Greenbone task identity.');
  return withClaimLock(pool,claimKey,async (client,row) => {
    if (row.remote_task_id === taskId &&
        ['remote-created','running','needs-reconciliation'].includes(row.state)) {
      return {state:row.state, taskId, unchanged:true};
    }
    if (row.state !== 'reserved' || row.remote_task_id !== null)
      throw Error('Remote task identity already exists or claim is not reservable.');
    const updated = await client.query(
      "UPDATE public.external_scan_dispatch_claims SET remote_task_id=$2,state='remote-created',updated_at=now() WHERE claim_key=$1 AND state='reserved' AND remote_task_id IS NULL RETURNING claim_key",
      [claimKey,taskId],
    );
    if (updated.rows.length !== 1) throw Error('Concurrent task identity change.');
    await client.query(
      "INSERT INTO public.external_scan_dispatch_events(claim_key,event_type,remote_task_id) VALUES ($1,'task-recorded',$2)",
      [claimKey,taskId],
    );
    return {state:'remote-created',taskId,unchanged:false};
  });
}

/**
 * Hold a disputed or timed-out launch. Never clears the slot or remote ID.
 * Calling this is safe after a create/start timeout: the operator can inspect
 * the task by ID (if known) and reconcile without launching another scan.
 */
export async function flagExternalScanReconciliation(pool, claimKey, reason) {
  if (typeof reason !== 'string' || reason.length < 1 || reason.length > 500)
    throw Error('A bounded reconciliation reason is required.');
  return withClaimLock(pool,claimKey,async (client,row) => {
    if (!['reserved','remote-created','running','needs-reconciliation'].includes(row.state))
      throw Error('Cannot change a terminal scan to uncertain.');
    await client.query(
      "UPDATE public.external_scan_dispatch_claims SET state='needs-reconciliation',updated_at=now() WHERE claim_key=$1",
      [claimKey],
    );
    await client.query(
      "INSERT INTO public.external_scan_dispatch_events(claim_key,event_type,remote_task_id,note) VALUES ($1,'needs-reconciliation',$2,$3)",
      [claimKey,row.remote_task_id,reason],
    );
    return {state:'needs-reconciliation',taskId:row.remote_task_id};
  });
}

/**
 * Read-only status and last 20 audit events; does not create schema or
 * hydrate the platform store. Caller must authenticate before invoking.
 */
export async function inspectExternalScanReconciliation(pool) {
  if (!pool?.query) throw Error('PostgreSQL pool unavailable.');
  const slot = await pool.query(
    'SELECT s.claim_key,s.updated_at AS slot_updated_at,c.company_id,c.target,c.nessus_scan_id,c.nessus_occurrence_at,c.state,c.remote_task_id,c.created_at,c.updated_at FROM public.external_scan_dispatch_slot s LEFT JOIN public.external_scan_dispatch_claims c ON c.claim_key=s.claim_key WHERE s.slot_id=1'
  );
  if (slot.rows.length !== 1) throw Error('External dispatch slot migration missing.');
  const events = slot.rows[0].claim_key ? await pool.query(
    'SELECT event_type,remote_task_id,note,recorded_at FROM public.external_scan_dispatch_events WHERE claim_key=$1 ORDER BY event_id DESC LIMIT 20',
    [slot.rows[0].claim_key],
  ) : {rows:[]};
  return {slot:slot.rows[0],events:events.rows};
}
