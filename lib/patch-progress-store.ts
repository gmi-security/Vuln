import {randomUUID} from 'node:crypto';
import type {Pool} from 'pg';
import {markReappearances,summarizeProgress,type ProgressScope,type ProgressTicket} from './patch-progress';
import type {ProgressCollection,ProgressTrend} from './patch-progress-sources';

const ticketMeta=(t:ProgressTicket)=>({ticketId:t.ticketId,ticketUrl:t.ticketUrl,ticketStatus:t.ticketStatus,closed:t.closed,
  createdAt:t.createdAt,originalDevices:t.hostCount,title:typeof t.packet.title==='string'?t.packet.title.slice(0,300):'Patch request',
  cves:Array.isArray(t.packet.cves)?t.packet.cves.slice(0,1000):[t.packet.cve].filter(Boolean)});
export async function recordProgressAttempt(db:Pool,scope:ProgressScope){
  const t=scope.ticket;
  await db.query(`INSERT INTO patch_progress_tickets(kind,request_id,company_id,ticket_id,scope_hash,metadata,last_attempt_at,check_state,error)
    VALUES($1,$2,$3,$4,$5,$6::jsonb,now(),$7,$8) ON CONFLICT(kind,request_id) DO UPDATE SET
    company_id=EXCLUDED.company_id,ticket_id=EXCLUDED.ticket_id,scope_hash=EXCLUDED.scope_hash,metadata=EXCLUDED.metadata,
    latest_evaluation=CASE WHEN patch_progress_tickets.scope_hash=EXCLUDED.scope_hash AND patch_progress_tickets.company_id=EXCLUDED.company_id THEN patch_progress_tickets.latest_evaluation ELSE NULL END,
    last_attempt_at=now(),check_state=EXCLUDED.check_state,error=EXCLUDED.error`,
    [t.kind,t.id,t.companyId,t.ticketId,t.scopeHash,JSON.stringify(ticketMeta(t)),scope.error?'baseline-unavailable':'pending',scope.error||null]);
}

/** Chunks can be retried after a crash; readers cannot see them before the final short commit. */
export async function saveProgressCollection(db:Pool,scope:ProgressScope,collection:ProgressCollection){
  const t=scope.ticket;
  const priorClear=(await db.query(`SELECT DISTINCT x.pair_key FROM patch_progress_transitions x JOIN patch_progress_evaluations e ON e.id=x.evaluation_id WHERE x.kind=$1 AND x.request_id=$2 AND x.scope_hash=$3 AND x.state='clear' AND e.company_id=$4`,[t.kind,t.id,t.scopeHash,t.companyId])).rows;
  markReappearances(collection.rows,new Set(priorClear.map(r=>r.pair_key)));
  const summary=summarizeProgress(collection.rows);
  const {rows:[evaluation]}=await db.query(`INSERT INTO patch_progress_evaluations(id,kind,request_id,scope_hash,fingerprint,summary,new_devices,source_times,expected_rows,source_captured_at,company_id)
    VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10,$11) ON CONFLICT(kind,request_id,company_id,scope_hash,fingerprint) DO UPDATE SET fingerprint=EXCLUDED.fingerprint RETURNING id,completed_at`,
    [randomUUID(),t.kind,t.id,t.scopeHash,collection.fingerprint,JSON.stringify(summary),JSON.stringify(collection.newDevices),JSON.stringify(collection.sourceTimes),collection.rows.length,collection.capturedAt,t.companyId]);
  {
    for(let offset=0;offset<collection.rows.length;offset+=500){
      await db.query(`INSERT INTO patch_progress_observations(evaluation_id,ordinal,pair_key,state,observation)
        SELECT $1,v.ordinal,v.key,v.state,v.observation FROM jsonb_to_recordset($2::jsonb) v(ordinal integer,key text,state text,observation jsonb)
        ON CONFLICT(evaluation_id,ordinal) DO NOTHING`,[evaluation.id,JSON.stringify(collection.rows.slice(offset,offset+500).map((r,i)=>({ordinal:offset+i,key:r.key,state:r.state,observation:r})))]);
    }
  }
  const client=await db.connect();
  try{
    await client.query("BEGIN; SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='2s'");
    const locked=(await client.query('SELECT scope_hash,company_id,latest_evaluation FROM patch_progress_tickets WHERE kind=$1 AND request_id=$2 FOR UPDATE',[t.kind,t.id])).rows[0];
    if(locked?.scope_hash!==t.scopeHash||locked.company_id!==t.companyId)throw Error('Ticket scope changed during progress collection.');
    const newer=(await client.query('SELECT 1 FROM patch_progress_evaluations WHERE id=$1 AND source_captured_at>$2::timestamptz',[locked.latest_evaluation,collection.capturedAt])).rowCount;
    if(newer)throw Error('A newer completed comparison is already available.');
    if(!evaluation.completed_at){
      const count=Number((await client.query('SELECT count(*) n FROM patch_progress_observations WHERE evaluation_id=$1',[evaluation.id])).rows[0].n);
      if(count!==collection.rows.length)throw Error('Incomplete progress evaluation.');
      await client.query(`INSERT INTO patch_progress_transitions(kind,request_id,scope_hash,pair_key,evaluation_id,state,observed_at)
        SELECT $1,$2,$3,n.pair_key,$4,n.state,(n.observation->>'assessmentAt')::timestamptz FROM patch_progress_observations n
        LEFT JOIN patch_progress_observations p ON p.evaluation_id=$5::uuid AND p.pair_key=n.pair_key
        WHERE n.evaluation_id=$4 AND n.state IS DISTINCT FROM p.state ON CONFLICT DO NOTHING`,[t.kind,t.id,t.scopeHash,evaluation.id,locked.latest_evaluation]);
      await client.query('UPDATE patch_progress_evaluations SET completed_at=now() WHERE id=$1',[evaluation.id]);
    }
    await client.query("UPDATE patch_progress_tickets SET latest_evaluation=$3,check_state='ready',error=NULL WHERE kind=$1 AND request_id=$2",[t.kind,t.id,evaluation.id]);
    await client.query('COMMIT');
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
  // Keep current and previous detail sets. Summaries and state transitions remain.
  await db.query(`DELETE FROM patch_progress_observations WHERE evaluation_id IN (
    SELECT id FROM patch_progress_evaluations WHERE kind=$1 AND request_id=$2 AND completed_at IS NOT NULL
    ORDER BY completed_at DESC OFFSET 2)`,[t.kind,t.id]);
}
export async function saveProgressTrends(db:Pool,companyId:string,trends:ProgressTrend[]){
  if(!trends.length)return;
  await db.query(`INSERT INTO patch_progress_trends(company_id,source,generation,observed_at,count,unit)
    SELECT $1,v.source,v.generation,v."observedAt",v.count,v.unit FROM jsonb_to_recordset($2::jsonb)
    v(source text,generation text,"observedAt" timestamptz,count bigint,unit text) ON CONFLICT DO NOTHING`,[companyId,JSON.stringify(trends)]);
}

export async function readPatchProgress(db:Pool,companyId:string,options:{offset?:number;requestId?:string;kind?:string;detailOffset?:number}={}){
  const client=await db.connect();
  try{
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='5s'");
    if(!(await client.query('SELECT id FROM app_companies WHERE id=$1',[companyId])).rowCount)throw Error('Unknown customer.');
    const ready=(await client.query("SELECT to_regclass('public.patch_progress_tickets') present")).rows[0].present;
    if(!ready){await client.query('COMMIT');return {state:'not-installed',tickets:[],trends:[],hasMore:false};}
    if(options.requestId){
      const rows=(await client.query(`SELECT o.observation FROM patch_progress_tickets t JOIN patch_progress_evaluations e ON e.id=t.latest_evaluation AND e.completed_at IS NOT NULL AND e.company_id=t.company_id AND e.scope_hash=t.scope_hash
        JOIN patch_progress_observations o ON o.evaluation_id=e.id WHERE t.company_id=$1 AND t.request_id=$2::uuid AND t.kind=$3
        ORDER BY o.ordinal LIMIT 101 OFFSET $4`,[companyId,options.requestId,options.kind,options.detailOffset||0])).rows;
      await client.query('COMMIT');return {state:'available',rows:rows.slice(0,100).map(r=>r.observation),hasMore:rows.length>100};
    }
    const tickets=(await client.query(`SELECT t.kind,t.request_id AS "requestId",t.metadata,t.check_state AS "checkState",t.error,t.last_attempt_at AS "lastAttemptAt",
      e.summary,e.new_devices AS "newDevices",e.source_times AS "sourceTimes",e.completed_at AS "checkedAt"
      FROM patch_progress_tickets t LEFT JOIN patch_progress_evaluations e ON e.id=t.latest_evaluation AND e.completed_at IS NOT NULL AND e.company_id=t.company_id AND e.scope_hash=t.scope_hash
      WHERE t.company_id=$1 ORDER BY t.ticket_id DESC,t.kind,t.request_id LIMIT 21 OFFSET $2`,[companyId,options.offset||0])).rows;
    const trends=(await client.query(`SELECT source,observed_at AS "observedAt",count::float8 AS count,unit FROM
      (SELECT *,row_number() OVER(PARTITION BY source ORDER BY observed_at DESC) n FROM patch_progress_trends WHERE company_id=$1) h
      WHERE n<=90 ORDER BY source,observed_at`,[companyId])).rows;
    const history=(await client.query(`SELECT e.completed_at AS "checkedAt",e.summary,e.request_id AS "requestId",e.kind FROM patch_progress_evaluations e JOIN patch_progress_tickets t ON t.kind=e.kind AND t.request_id=e.request_id
      WHERE t.company_id=$1 AND e.company_id=t.company_id AND e.scope_hash=t.scope_hash AND e.completed_at IS NOT NULL ORDER BY e.completed_at DESC LIMIT 100`,[companyId])).rows;
    await client.query('COMMIT');return {state:'available',tickets:tickets.slice(0,20),hasMore:tickets.length>20,trends,history};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
}
