import type {Pool,PoolClient} from 'pg';
import {createHash} from 'node:crypto';
import {assessProgress,type ProgressEvidence,type ProgressScope,type ProgressObservation} from './patch-progress';
import type {Finding} from './types';
import {storedSpotlightContext,storedSpotlightProof,type StoredSpotlightScopeProof} from './customer-stored-spotlight';
import {matchesSpotlightTenant} from './spotlight-summary-model';
import {loadReviewedScannerRoutes} from './customer-scanner-routing-server';
import {nessusEvidenceScope} from './nessus-evidence-scope';

const iso=(value:unknown)=>value?new Date(String(value)).toISOString():null;
const fingerprint=(value:unknown)=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
export type ProgressCollection={rows:ProgressObservation[];fingerprint:string;newDevices:Record<string,number|null>;sourceTimes:Record<string,string|null>;capturedAt:string};

export function defenderProgressEvidence(f:Finding|undefined,run:{id:string;published:boolean;finishedAt:string}|null,device:{lastSeen?:string|null}|undefined,present:boolean):ProgressEvidence|null {
  if(!f?.defender||!run)return null;
  const heartbeat=device?.lastSeen||null;
  return {complete:run.published&&!!heartbeat&&Date.parse(heartbeat)<=Date.parse(run.finishedAt),scopeMatches:f.defender.runId===run.id,generation:run.id,
    assessmentAt:heartbeat,present,covered:!!device&&!!heartbeat&&Date.parse(heartbeat)<=Date.parse(run.finishedAt),
    reason:!device?'Device was not included in the completed inventory.':!heartbeat?'Device assessment time is unavailable.':undefined};
}
export function nessusProgressEvidence(f:Finding|undefined,scans:Map<string,{completedAt:string;imported:boolean;version:number}>,allowed:Set<string>):ProgressEvidence|null {
  if(!f?.nessusObservations)return null;
  const entries=Object.entries(f.nessusObservations);if(!entries.length)return null;
  const valid=entries.filter(([id,o])=>{const scan=scans.get(id);return allowed.has(id)&&scan?.imported&&scan.version===1&&scan.completedAt===o.observedAt;});
  const positives=valid.filter(([,o])=>o.present),allCovered=valid.length===entries.length;
  // Every policy which reported this finding must provide its own later negative.
  const selected=positives.length?positives:valid;
  const dates=selected.map(([,o])=>o.observedAt).sort();
  return {complete:true,scopeMatches:positives.length>0||allCovered,generation:fingerprint(entries),present:positives.length>0,
    covered:allCovered,assessmentAt:positives.length?dates.at(-1)||null:dates[0]||null,
    reason:!allCovered?'One or more Nessus scan policies have no verified current assessment.':undefined};
}

/** Ticket-sized reads only. This never hydrates the platform or invokes a provider. */
export async function collectPatchProgress(db:Pool,scope:ProgressScope):Promise<ProgressCollection> {
  const company=scope.ticket.companyId,hasCs=scope.pairs.some(p=>p.source==='crowdstrike');
  const context=hasCs?await storedSpotlightContext(company):null;
  const nessusRoutes=scope.pairs.some(p=>p.source==='nessus')?await loadReviewedScannerRoutes('nessus'):[];
  const client=await db.connect(),rows:ProgressObservation[]=[],newDevices:Record<string,number|null>={},sourceTimes:Record<string,string|null>={};
  const capturedAt=new Date().toISOString(),deadline=Date.now()+90_000;
  try{
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL idle_in_transaction_session_timeout='20s'");
    const tables=(await client.query(`SELECT to_regclass('public.defender_connections') defender,to_regclass('public.spotlight_import_current') spotlight`)).rows[0];
    const exists=(await client.query('SELECT id FROM app_companies WHERE id=$1',[company])).rowCount;
    if(!exists)throw Error('Customer is unavailable.');
    let defender:{id:string;published:boolean;finishedAt:string}|null=null;
    if(tables.defender&&scope.pairs.some(p=>p.source==='defender')){
      const r=(await client.query(`SELECT r.id,r.finished_at,r.status,c.revision=r.revision AS matches,
        m.payload->'meta'->'defenderGenerations'->>$1 AS published FROM defender_connections c
        JOIN defender_import_runs r ON r.id=c.current_run CROSS JOIN app_store_metadata m
        WHERE c.company_id=$1 AND m.id=1`,[company])).rows[0];
      if(r)defender={id:r.id,published:r.status==='succeeded'&&r.matches&&r.published===r.id,finishedAt:iso(r.finished_at)!};
      sourceTimes.defender=defender?.published?defender.finishedAt:null;
    }
    const scans=new Map<string,{completedAt:string;imported:boolean;version:number}>(),allowed=new Set<string>();
    if(scope.pairs.some(p=>p.source==='nessus')){
      const saved=(await client.query(`SELECT payload FROM app_scans WHERE company_id=$1 AND connector='nessus' ORDER BY created_at DESC LIMIT 10001`,[company])).rows;
      if(saved.length>10000)throw Error('Nessus scan history exceeds comparison budget.');
      for(const {payload:s} of saved){
        const id=String(s.vendor?.nessusScanId);
        if(!s.vendor?.imported||!s.completedAt||s.status!=='Completed')continue;
        const prior=scans.get(id);
        const matches=nessusRoutes?.some(route=>route.companyId===company&&s.vendor.nessusProgressScope===nessusEvidenceScope(route));
        if(!prior||s.completedAt>prior.completedAt){
          scans.set(id,{completedAt:s.completedAt,imported:true,version:s.vendor.nessusEvidenceVersion});
          if(matches)allowed.add(id);else allowed.delete(id);
        }else if(s.completedAt===prior.completedAt&&!matches)allowed.delete(id);
      }
      sourceTimes.nessus=[...scans.values()].map(s=>s.completedAt).sort().at(-1)||null;
    }
    let cs:StoredSpotlightScopeProof|null=null,csAbsenceReady=false;
    if(hasCs&&tables.spotlight&&context?.reviewed){
      const current=(await client.query('SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1',[company])).rows[0];
      if(current){
        cs=await storedSpotlightProof(client,context,company,current.run_id,{allowEmpty:true});
        const run=(await client.query('SELECT started_at,finished_at,expected_count FROM spotlight_import_runs WHERE id=$1',[current.run_id])).rows[0];
        sourceTimes.crowdstrike=iso(run.finished_at);
        if(Number(run.expected_count)===0){
          if((await client.query('SELECT 1 FROM spotlight_import_records WHERE run_id=$1 LIMIT 1',[current.run_id])).rowCount)throw Error('Empty generation contains source records.');
          csAbsenceReady=Date.parse(iso(run.started_at)!)>Date.parse(scope.ticket.createdAt);
        }else{
          const summary=(await client.query(`SELECT g.summary->'vendorScope' scope,g.source_rows FROM spotlight_summary_current s JOIN spotlight_summary_generations g USING(company_id,run_id,model_version) WHERE s.company_id=$1 AND s.run_id=$2`,[company,current.run_id])).rows[0];
          if(!cs||!summary||!matchesSpotlightTenant(summary.scope,cs.cid,summary.source_rows))cs=null;
          else csAbsenceReady=summary.scope.localPlaceholderRows===0&&Date.parse(iso(run.started_at)!)>Date.parse(scope.ticket.createdAt);
        }
      }
    }
    const savedProof=scope.ticket.packet.storedSpotlightScope as StoredSpotlightScopeProof|undefined;
    if(cs&&savedProof&&(savedProof.cid!==cs.cid||savedProof.bindingKey!==cs.bindingKey||savedProof.companyId!==company))cs=null;
    for(let offset=0;offset<scope.pairs.length;offset+=250){
      if(Date.now()>deadline)throw Error('Patch comparison exceeded its bounded work window.');
      const batch=scope.pairs.slice(offset,offset+250),ids=[...new Set(batch.map(p=>p.findingId).filter(Boolean))];
      const findings:Finding[]=ids.length?(await client.query('SELECT payload FROM app_findings WHERE company_id=$1 AND id=ANY($2::text[])',[company,ids])).rows.map(r=>r.payload):[];
      const byId=new Map(findings.map(f=>[f.id,f]));
      const deviceIds=[...new Set(findings.map(f=>f.defender?.deviceId).filter(Boolean))];
      const devices=new Map<string,{lastSeen?:string|null}>(),positives=new Set<string>();
      if(defender?.published&&deviceIds.length){
        for(const r of (await client.query('SELECT device_id,record FROM defender_devices WHERE run_id=$1 AND device_id=ANY($2::text[])',[defender.id,deviceIds])).rows)devices.set(r.device_id,r.record);
        for(const r of (await client.query(`SELECT DISTINCT device_id,cve FROM defender_records WHERE run_id=$1 AND device_id=ANY($2::text[]) AND cve=ANY($3::text[]) LIMIT 10001`,[defender.id,deviceIds,[...new Set(batch.map(p=>p.cve))]])).rows){positives.add(JSON.stringify([r.device_id,r.cve]));}
        if(positives.size>10000)throw Error('Defender comparison batch exceeds its evidence budget.');
      }
      const csRows=new Map<string,{present:boolean;suppressed:boolean;assessment:string|null}>();
      const csPairs=batch.filter(p=>p.source==='crowdstrike'&&p.cid===cs?.cid);
      if(cs&&csPairs.length){
        const result=(await client.query(`SELECT raw->>'aid' host,cve,
          bool_or(status IN ('open','reopen') AND lower(raw->>'status')=status AND raw->'suppression_info'->>'is_suppressed'='false') present,
          bool_or(COALESCE(raw->'suppression_info'->>'is_suppressed','unknown')<>'false') suppressed,
          max(raw->>'updated_timestamp') assessment
          FROM spotlight_import_records WHERE run_id=$1 AND tenant_key=$2 AND company_id=$2 AND cve=ANY($3::text[])
          AND lower(raw->>'cid')=$4 AND raw->>'aid'=ANY($5::text[]) AND raw->>'id'=source_id
          AND upper(raw->'cve'->>'id')=cve GROUP BY raw->>'aid',cve LIMIT 10001`,
          [cs.runId,company,[...new Set(csPairs.map(p=>p.cve))],cs.cid,[...new Set(csPairs.map(p=>p.hostId))]])).rows;
        if(result.length>10000)throw Error('CrowdStrike comparison batch exceeds its evidence budget.');
        for(const r of result)csRows.set(JSON.stringify([r.host,r.cve]),{present:r.present,suppressed:r.suppressed,assessment:r.assessment});
      }
      for(const p of batch){
        let evidence:ProgressEvidence|null=null;
        const f=p.findingId?byId.get(p.findingId):undefined;
        const valid=f?.companyId===company&&f.asset===p.hostId&&f.cve===p.cve?f:undefined;
        if(p.source==='defender')evidence=defenderProgressEvidence(valid,defender,devices.get(valid?.defender?.deviceId||''),positives.has(JSON.stringify([valid?.defender?.deviceId,p.cve])));
        if(p.source==='nessus')evidence=nessusProgressEvidence(valid,scans,allowed);
        if(p.source==='crowdstrike'&&cs&&p.cid===cs.cid){const found=csRows.get(JSON.stringify([p.hostId,p.cve]));evidence={complete:true,scopeMatches:true,generation:cs.runId,present:!!found?.present,covered:false,suppressed:found?.suppressed,
          assessmentAt:sourceTimes.crowdstrike,absenceIsFix:csAbsenceReady,reason:'Waiting for a complete CrowdStrike import started after ticket creation, without unresolved source records.'};}
        rows.push(assessProgress(p,scope.ticket.createdAt,evidence));
      }
      await new Promise(resolve=>setImmediate(resolve));
    }
    // Additional devices are outside the ticket baseline; count them separately.
    const cves=[...new Set(scope.pairs.map(p=>p.cve))];
    for(const source of new Set(scope.pairs.map(p=>p.source)))newDevices[source]=null;
    if(cves.length<=1000&&defender?.published){
      const originalIds=(await client.query('SELECT DISTINCT payload->\'defender\'->>\'deviceId\' id FROM app_findings WHERE company_id=$1 AND id=ANY($2::text[])',[company,scope.pairs.filter(p=>p.source==='defender').map(p=>p.findingId).filter(Boolean)])).rows.map(r=>r.id).filter(Boolean);
      newDevices.defender=Number((await client.query('SELECT count(DISTINCT device_id)::int n FROM defender_records WHERE run_id=$1 AND cve=ANY($2::text[]) AND NOT(device_id=ANY($3::text[]))',[defender.id,cves,originalIds])).rows[0].n);
    }
    if(cves.length<=1000&&cs){newDevices.crowdstrike=Number((await client.query(`SELECT count(DISTINCT raw->>'aid')::int n FROM spotlight_import_records WHERE run_id=$1 AND tenant_key=$2 AND company_id=$2 AND cve=ANY($3::text[]) AND lower(raw->>'cid')=$4 AND status IN ('open','reopen') AND raw->'suppression_info'->>'is_suppressed'='false' AND NOT(raw->>'aid'=ANY($5::text[]))`,[cs.runId,company,cves,cs.cid,scope.pairs.filter(p=>p.source==='crowdstrike').map(p=>p.hostId)])).rows[0].n);}
    await client.query('COMMIT');
    return {rows,fingerprint:fingerprint([scope.ticket.scopeHash,rows.map(r=>[r.key,r.state,r.assessmentAt,r.generation,r.reason]),newDevices,sourceTimes]),newDevices,sourceTimes,capturedAt};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
}

export type ProgressTrend={source:string;generation:string;observedAt:string;count:number;unit:string};
/** Source-independent counts from committed platform records plus the saved Spotlight summary.
 * One bounded SQL aggregate per changed publication, outside both HTTP and the save transaction. */
export async function collectProgressTrends(client:PoolClient,company:string):Promise<ProgressTrend[]> {
  const out:ProgressTrend[]=[];
  const configuredCs=(await client.query("SELECT source_scope FROM customer_spotlight_routes WHERE company_id=$1 AND enabled AND provider='crowdstrike'",[company])).rows[0];
  let cs=configuredCs?(await client.query(`SELECT g.run_id,g.source_completed_at,g.summary,g.source_rows FROM spotlight_summary_current c JOIN spotlight_summary_generations g USING(company_id,run_id,model_version)
    JOIN spotlight_import_current i ON i.tenant_key=c.company_id AND i.run_id=c.run_id WHERE c.company_id=$1`,[company])).rows[0]:null;
  if(configuredCs){
    const run=(await client.query(`SELECT r.id,r.status,r.finished_at,r.expected_count,r.hydrated_count,r.checkpoint_version,p.cid
      FROM spotlight_import_current i JOIN spotlight_import_runs r ON r.id=i.run_id AND r.tenant_key=i.tenant_key
      JOIN spotlight_import_run_scopes p ON p.run_id=r.id AND p.company_id=i.tenant_key WHERE i.tenant_key=$1`,[company])).rows[0];
    if(!run||run.status!=='completed'||run.checkpoint_version!==4||run.cid!==configuredCs.source_scope||run.expected_count===null||Number(run.expected_count)!==Number(run.hydrated_count))return [];
    if(Number(run.expected_count)===0){
      if((await client.query('SELECT 1 FROM spotlight_import_records WHERE run_id=$1 LIMIT 1',[run.id])).rowCount)return [];
      cs={run_id:run.id,source_completed_at:run.finished_at,summary:{deviceCveFindings:0},source_rows:0};
    }else if(!cs||!matchesSpotlightTenant(cs.summary.vendorScope,configuredCs.source_scope,cs.source_rows))return [];
  }
  // A failed/in-flight import cannot become a successful lower-count observation.
  const scans=(await client.query(`SELECT id,connector,status,created_at,payload->>'completedAt' completed_at,
    jsonb_build_object('id',id,'vendor',jsonb_build_object('imported',payload->'vendor'->'imported')) payload
    FROM app_scans WHERE company_id=$1 AND connector NOT IN ('spiderfoot','artemis','crowdstrike')
    ORDER BY connector,id LIMIT 10001`,[company])).rows;
  if(scans.length>10000)return [];
  const completed=scans.filter(s=>s.status==='Completed'&&(s.connector!=='nessus'||s.payload.vendor?.imported)&&s.completed_at);
  for(const s of scans.filter(s=>!completed.includes(s))){
    const last=completed.filter(c=>c.connector===s.connector).map(c=>Math.max(Date.parse(c.created_at),Date.parse(c.completed_at))).sort((a,b)=>b-a)[0];
    if(!last||Date.parse(s.created_at)>=last)return [];
  }
  if(!completed.length&&!cs)return [];
  const stamp=fingerprint([completed.map(s=>[s.connector,s.payload.id,s.completed_at]),cs?.run_id]);
  if((await client.query("SELECT 1 FROM patch_progress_trends WHERE company_id=$1 AND source='total' AND generation=$2",[company,stamp])).rowCount)return [];
  // The live finding view only exposes the committed generation. CS has its own
  // complete-generation store; do not add its legacy platform copy twice.
  const counts=(await client.query(`SELECT connector,count(*)::float8 n FROM app_findings WHERE company_id=$1
    AND status IN ('Open','In Remediation') AND connector NOT IN ('spiderfoot','artemis')
    AND ($2::boolean=false OR connector<>'crowdstrike') GROUP BY connector`,[company,!!cs])).rows;
  const observedAt=new Date().toISOString();
  for(const s of completed)if(!counts.some(c=>c.connector===s.connector))counts.push({connector:s.connector,n:0});
  for(const c of counts)out.push({source:c.connector,generation:stamp,observedAt,count:Number(c.n),unit:'open platform findings'});
  if(cs)out.push({source:'crowdstrike',generation:stamp,observedAt,count:Number(cs.summary.deviceCveFindings),unit:'open device/CVE findings'});
  if(out.some(r=>!Number.isSafeInteger(r.count)||r.count<0))throw Error('Invalid saved open count.');
  out.unshift({source:'total',generation:stamp,observedAt,count:out.reduce((n,r)=>n+r.count,0),unit:'open findings across imported sources; source populations may overlap'});
  return out;
}
