import {randomUUID} from 'node:crypto';
import type {Pool} from 'pg';
import {applicationDatabase} from './persist';
import {patchTicketDatabase,savedConnection} from './patch-ticket-store';
import {elasticVulnEnabled} from './elastic-vuln-server';
import {progressScope,type ProgressTicket} from './patch-progress';
import {collectPatchProgress,collectProgressTrends} from './patch-progress-sources';
import {recordProgressAttempt,saveProgressCollection,saveProgressTrends} from './patch-progress-store';

/** No connector download, draft generation or ConnectWise mutation occurs here. */
export async function runPatchProgressWorker(db:Pool){
  if(!(await db.query("SELECT to_regclass('public.patch_progress_worker') present")).rows[0].present)return;
  const owner=randomUUID(),claim=(await db.query(`UPDATE patch_progress_worker SET lease_until=now()+interval '10 minutes',lease_owner=$1
    WHERE id=1 AND (lease_until IS NULL OR lease_until<now()) RETURNING ticket_cursor,company_cursor`,[owner])).rows[0];
  if(!claim)return;
  const deadline=Date.now()+120_000;
  try{
    const companies=(await db.query('SELECT id FROM app_companies WHERE id>$1 ORDER BY id LIMIT 10',[claim.company_cursor])).rows;
    for(const company of companies){
      const client=await db.connect();let trends;
      try{await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='5s'");trends=await collectProgressTrends(client,company.id);await client.query('COMMIT');}
      catch{await client.query('ROLLBACK').catch(()=>{});console.error('[patch-progress] A customer count is pending; previous history retained.');}finally{client.release();}
      if(trends)await saveProgressTrends(db,company.id,trends);
    }
    await db.query('UPDATE patch_progress_worker SET company_cursor=$2 WHERE id=1 AND lease_owner=$1',[owner,companies.length<10?'':companies.at(-1).id]);
    const connection=await savedConnection().catch(()=>null);if(!connection)return;
    const ticketDb=await patchTicketDatabase();
    const candidates=(await ticketDb.query(`SELECT * FROM (
      SELECT 'single:'||id::text cursor,'single' kind,id FROM patch_ticket_requests WHERE state='created' AND ticket_id IS NOT NULL AND cw_target=$2 AND packet->>'appCompanyId' IS NOT NULL
      UNION ALL SELECT 'group:'||id::text cursor,'group' kind,id FROM patch_group_ticket_requests WHERE state='created' AND ticket_id IS NOT NULL AND cw_target=$2 AND packet->>'appCompanyId' IS NOT NULL
      ) q WHERE cursor>$1 ORDER BY cursor LIMIT 20`,[claim.ticket_cursor,connection.target])).rows;
    let cursor=claim.ticket_cursor,processed=0;
    for(const candidate of candidates){
      if(processed>=2||Date.now()>deadline)break;
      const recent=(await db.query(`SELECT last_attempt_at FROM patch_progress_tickets WHERE kind=$1 AND request_id=$2 AND last_attempt_at>now()-interval '30 minutes'`,[candidate.kind,candidate.id])).rowCount;
      cursor=candidate.cursor;if(recent)continue;
      const table=candidate.kind==='group'?'patch_group_ticket_requests':'patch_ticket_requests';
      const audit=candidate.kind==='group'?'patch_group_ticket_audit':'patch_ticket_audit';
      const r=(await ticketDb.query(`SELECT id,packet->>'appCompanyId' company_id,ticket_id,ticket_url,ticket_status,closed,host_count,scope_hash,
        (SELECT max(created_at) FROM ${audit} WHERE request_id=t.id AND action='ticket.created') created_at,
        CASE WHEN pg_column_size(packet)<8388608 THEN packet-'csv'-'body'-'warnings' ELSE jsonb_build_object('appCompanyId',packet->>'appCompanyId') END packet
        FROM ${table} t WHERE id=$1 AND cw_target=$2 AND state='created' AND ticket_id IS NOT NULL`,[candidate.id,connection.target])).rows[0];
      if(!r)continue;
      const t:ProgressTicket={id:r.id,kind:candidate.kind,companyId:r.company_id,ticketId:r.ticket_id,ticketUrl:r.ticket_url,ticketStatus:r.ticket_status,closed:r.closed,
        hostCount:r.host_count,scopeHash:r.scope_hash,createdAt:r.created_at?new Date(r.created_at).toISOString():'',packet:r.packet};
      const scope=progressScope(t);processed++;
      await recordProgressAttempt(db,scope);
      if(!scope.error){try{const result=await collectPatchProgress(db,scope);await saveProgressCollection(db,scope,result);}
        catch{await db.query("UPDATE patch_progress_tickets SET check_state='failed',error='The latest comparison could not complete. Previous evidence is retained; the worker will retry.' WHERE kind=$1 AND request_id=$2",[t.kind,t.id]);}}
    }
    if(candidates.length<20&&cursor===candidates.at(-1)?.cursor||!candidates.length)cursor='';
    await db.query('UPDATE patch_progress_worker SET ticket_cursor=$2 WHERE id=1 AND lease_owner=$1',[owner,cursor]);
  }finally{await db.query('UPDATE patch_progress_worker SET lease_until=NULL,lease_owner=NULL WHERE id=1 AND lease_owner=$1',[owner]);}
}
const runtime=globalThis as typeof globalThis&{__patchProgress?:{timer?:ReturnType<typeof setInterval>;working?:Promise<void>}};
export function startPatchProgressWorker(){
  const state=runtime.__patchProgress??={};
  if(state.timer||process.env.VULN_RUNTIME_ROLE==='web'||process.env.VULN_DISABLE_SCHEDULER==='true'||!elasticVulnEnabled())return;
  const trigger=()=>{const db=applicationDatabase();if(state.working||!db)return;state.working=runPatchProgressWorker(db).catch(()=>console.error('[patch-progress] Comparison worker failed; saved evidence remains available.')).finally(()=>{state.working=undefined;});};
  state.timer=setInterval(trigger,60_000);state.timer.unref();trigger();
}
