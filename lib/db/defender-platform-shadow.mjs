// Offline migration contract v1. No runtime imports, source refresh or schema creation.
import {randomUUID} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
const statuses=new Set(['Open','In Remediation','Risk Accepted','False Positive','Resolved']);
const severities=new Set(['Critical','High','Medium','Low','Info']);
function requireValue(value,message){if(!value)throw new Error(message);}
const string=value=>typeof value==='string'&&value.length>0;
const nullableString=value=>value===null||typeof value==='string';
const score=(value,max)=>typeof value==='number'&&Number.isFinite(value)&&value>=0&&value<=max;
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);

export function projectDefenderFinding(finding,companyId){
  requireValue(object(finding)&&finding.companyId===companyId,'Finding customer mismatch');
  requireValue(['id','cve','asset','connector','firstSeen','lastSeen'].every(k=>string(finding[k])),'Missing finding identity or chronology');
  requireValue(statuses.has(finding.status)&&nullableString(finding.assignee)&&nullableString(finding.resolvedAt),'Invalid workflow');
  requireValue(severities.has(finding.severity)&&severities.has(finding.riskPriority)&&score(finding.cvss,10)&&score(finding.realRisk,100),'Invalid saved assessment');
  const evidence=finding.defender;
  requireValue(object(evidence)&&['deviceId','runId','observedAt'].every(k=>string(evidence[k]))&&
    typeof evidence.active==='boolean'&&(evidence.cvss===null||score(evidence.cvss,10)),'Invalid Defender evidence');
  const {id,companyId:owner,cve,asset,connector,status,assignee,firstSeen,lastSeen,resolvedAt,
    severity,cvss,realRisk,riskPriority,defender,...detail}=finding;
  const {deviceId,runId,observedAt,active,cvss:sourceCvss,...sourceDetail}=evidence;
  return {id,companyId:owner,cve,asset,connector,status,assignee,firstSeen,lastSeen,resolvedAt,
    severity,cvss,realRisk,riskPriority,deviceId,runId,observedAt,active,sourceCvss,detail,sourceDetail};
}

// Parameterized per-finding lookups prevent stale statistics on freshly loaded
// tables from producing repeated whole-generation joins during batch verification.
export const reconstructShadowSql=`SELECT f.finding_id AS id,
  f.detail || jsonb_build_object('id',f.finding_id,'companyId',f.company_id,'cve',f.issue_key,'asset',f.asset_key,'connector',f.connector,
    'status',w.status,'assignee',w.assignee,'firstSeen',w.first_seen,'lastSeen',w.last_seen,'resolvedAt',w.resolved_at,
    'severity',a.severity,'cvss',a.cvss,'realRisk',a.real_risk,'riskPriority',a.risk_priority,
    'defender',e.detail || jsonb_build_object('deviceId',e.device_id,'runId',e.source_run,'observedAt',e.observed_at,'active',e.active,'cvss',e.source_cvss)) AS record
  FROM defender_shadow_findings f
  JOIN LATERAL (SELECT * FROM defender_shadow_workflow w WHERE w.company_id=f.company_id
    AND w.projection_id=f.projection_id AND w.finding_id=f.finding_id OFFSET 0) w ON true
  JOIN LATERAL (SELECT * FROM defender_shadow_assessments a WHERE a.company_id=f.company_id
    AND a.projection_id=f.projection_id AND a.finding_id=f.finding_id OFFSET 0) a ON true
  JOIN LATERAL (SELECT * FROM defender_shadow_evidence e WHERE e.company_id=f.company_id
    AND e.projection_id=f.projection_id AND e.finding_id=f.finding_id OFFSET 0) e ON true
  WHERE f.company_id=$1 AND f.projection_id=$2`;

const insertBatch=`WITH input AS MATERIALIZED (
 SELECT * FROM jsonb_to_recordset($3::jsonb) AS x(id text,"companyId" text,cve text,asset text,connector text,
 status text,assignee text,"firstSeen" text,"lastSeen" text,"resolvedAt" text,severity text,cvss float8,
 "realRisk" float8,"riskPriority" text,"deviceId" text,"runId" text,"observedAt" text,active boolean,
 "sourceCvss" float8,detail jsonb,"sourceDetail" jsonb)),
 core AS (INSERT INTO defender_shadow_findings SELECT $1,$2,id,cve,asset,connector,detail FROM input RETURNING finding_id),
 workflow AS (INSERT INTO defender_shadow_workflow SELECT $1,$2,id,status,assignee,"firstSeen","lastSeen","resolvedAt" FROM input RETURNING finding_id),
 assessment AS (INSERT INTO defender_shadow_assessments SELECT $1,$2,id,severity,cvss,"realRisk","riskPriority" FROM input RETURNING finding_id)
 INSERT INTO defender_shadow_evidence SELECT $1,$2,id,"deviceId",cve,"runId","observedAt",active,"sourceCvss","sourceDetail" FROM input`;

async function privateDatabase(client,kind){
  const {rows:[row]}=await client.query("SELECT current_database() AS db,current_setting('data_directory') AS dir,current_setting('listen_addresses') AS listen");
  requireValue(row.dir.startsWith('/home/codex/vuln-recovery/')&&!row.listen,'Private recovery cluster required');
  requireValue(kind==='target'?/^vuln2_shadow_test_[a-f0-9]+$/.test(row.db):
    row.db==='recovery_application'||/^vuln2_shadow_source_test_[a-f0-9]+$/.test(row.db),'Disposable target or restored source required');
  return row.db;
}

export async function readDefenderShadowTotals(client,companyId,projectionId){
  const {rows:[generation]}=await client.query(`SELECT state FROM defender_shadow_generations WHERE company_id=$1 AND projection_id=$2`,[companyId,projectionId]);
  requireValue(generation?.state==='verified','Verified customer projection required');
  const {rows}=await client.query(`SELECT w.status,a.severity,count(*)::int AS findings,
    count(DISTINCT f.issue_key)::int AS cves,count(DISTINCT f.asset_key)::int AS assets
    FROM defender_shadow_findings f JOIN defender_shadow_workflow w USING(company_id,projection_id,finding_id)
    JOIN defender_shadow_assessments a USING(company_id,projection_id,finding_id)
    WHERE f.company_id=$1 AND f.projection_id=$2 GROUP BY w.status,a.severity ORDER BY w.status,a.severity`,[companyId,projectionId]);
  // CVE/device values are per group, not additive across severity/status groups.
  return rows;
}

export async function buildDefenderPlatformShadow(source,target,companyId,{afterBatch,deadlineMs=300000}={}){
  requireValue(/^CO-[A-Za-z0-9-]+$/.test(companyId),'Explicit customer required');
  requireValue(Number.isInteger(deadlineMs)&&deadlineMs>0&&deadlineMs<=300000,'Invalid build deadline');
  const sourceDb=await privateDatabase(source,'source'),targetDb=await privateDatabase(target,'target');
  requireValue(sourceDb!==targetDb,'Separate target database required');
  await target.query("SET statement_timeout='15s'; SET lock_timeout='2s'");
  const projectionId=randomUUID(),started=Date.now();let created=false,count=0,batches=0,connectionError=false;
  const onDisconnect=()=>{connectionError=true;};source.on('error',onDisconnect);target.on('error',onDisconnect);
  const check=()=>{requireValue(!connectionError,'Shadow connection interrupted');requireValue(Date.now()-started<deadlineMs,'Shadow projection deadline exceeded');};
  try{
    await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await source.query("SET LOCAL statement_timeout='15s'; SET LOCAL idle_in_transaction_session_timeout='60s'");
    const {rows:[meta]}=await source.query(`SELECT data ? 'findings' AS override,data ? 'companies' AS company_override,
      data->'meta'->'defenderGenerations'->>$1 AS published,updated_at FROM vuln_store WHERE key='meta'`,[companyId]);
    requireValue(meta&&!meta.override&&!meta.company_override&&string(meta.published),'Unsupported snapshot or absent publication');
    const {rows:companies}=await source.query(`SELECT c->1->'isDemo' AS demo FROM vuln_store,
      LATERAL jsonb_array_elements(data) c WHERE key='companies:00' AND c->>0=$1 AND c->1->>'id'=$1`,[companyId]);
    requireValue(companies.length===1&&(companies[0].demo===false||companies[0].demo===null),'Known non-demo customer required');
    const {rows:[run]}=await source.query(`SELECT c.current_run::text AS id,c.revision=r.revision AS revision_matches
      FROM defender_connections c JOIN defender_import_runs r ON r.id=c.current_run AND r.company_id=c.company_id
      WHERE c.company_id=$1 AND r.status='succeeded'`,[companyId]);
    requireValue(run?.revision_matches&&run.id===meta.published,'Published and retained source generations must match');
    const {rows:buckets}=await source.query("SELECT key,jsonb_typeof(data) AS type FROM vuln_store WHERE key LIKE 'findings:%' ORDER BY key");
    requireValue(buckets.length===64&&buckets.every((r,i)=>r.key===`findings:${String(i).padStart(2,'0')}`&&r.type==='array'),'Unsupported findings buckets');
    await target.query(`INSERT INTO defender_shadow_generations(company_id,projection_id,model_version,source_run,snapshot_saved_at,state)
      VALUES($1,$2,1,$3,$4,'building')`,[companyId,projectionId,run.id,meta.updated_at]);created=true;
    for(const {key} of buckets){
      check();
      const {rows:[valid]}=await source.query(`SELECT count(*)::int AS n,bool_and(COALESCE(CASE WHEN jsonb_typeof(e)='array' THEN
        jsonb_array_length(e)=2 AND jsonb_typeof(e->0)='string' AND jsonb_typeof(e->1)='object' AND e->>0=e->1->>'id' ELSE false END,false)) AS valid
        FROM vuln_store,LATERAL jsonb_array_elements(data) e WHERE key=$1`,[key]);
      requireValue(valid.n<=20000&&(valid.n===0||valid.valid===true),'Malformed or oversized bucket');
      const {rows}=await source.query(`SELECT e->1 AS record FROM vuln_store,LATERAL jsonb_array_elements(data) e
        WHERE key=$1 AND e->1->>'companyId'=$2 AND (e->1 ? 'defender' OR e->1->>'connector'='defender')`,[key,companyId]);
      for(let offset=0;offset<rows.length;offset+=500){
        check();await source.query('SELECT 1'); // Keep the pinned read snapshot alive while writing each target batch.
        const originals=rows.slice(offset,offset+500).map(r=>r.record);
        const projected=originals.map(f=>projectDefenderFinding(f,companyId));count+=projected.length;
        requireValue(count<=500000,'Shadow projection record limit exceeded');
        await target.query('BEGIN');
        try{
          await target.query("SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='2s'");
          await target.query(insertBatch,[companyId,projectionId,JSON.stringify(projected)]);
          const {rows:copied}=await target.query(`${reconstructShadowSql} AND f.finding_id=ANY($3::text[])`,[companyId,projectionId,projected.map(f=>f.id)]);
          const expected=new Map(originals.map(f=>[f.id,f]));
          requireValue(copied.length===originals.length&&copied.every(r=>isDeepStrictEqual(r.record,expected.get(r.id))),'Full finding reconstruction differs');
          await target.query('COMMIT');
        }catch(error){await target.query('ROLLBACK');throw error;}
        batches++;await afterBatch?.({count,batches,elapsedMs:Date.now()-started});
      }
    }
    check();
    const counts=[];
    for(const table of ['findings','workflow','assessments','evidence']){
      check();await source.query('SELECT 1');
      const {rows:[row]}=await target.query(`SELECT count(*)::int AS n FROM defender_shadow_${table} WHERE company_id=$1 AND projection_id=$2`,[companyId,projectionId]);counts.push(row.n);
    }
    requireValue(counts.every(n=>n===count),'Shadow table counts differ');
    // This target is disposable and autovacuum is disabled in the recovery cluster.
    // Refresh narrow-column statistics after bulk loading, before aggregate verification.
    for(const [table,columns] of [['findings','company_id,projection_id,finding_id,issue_key,asset_key'],
      ['workflow','company_id,projection_id,finding_id,status'],['assessments','company_id,projection_id,finding_id,severity'],
      ['evidence','company_id,projection_id,finding_id,source_run,active']]){
      check();await source.query('SELECT 1');await target.query(`ANALYZE defender_shadow_${table} (${columns})`);
    }
    await target.query(`UPDATE defender_shadow_generations SET state='verified',finding_count=$3,verified_at=now()
      WHERE company_id=$1 AND projection_id=$2 AND state='building'`,[companyId,projectionId,count]);
    await source.query('ROLLBACK');
    return {companyId,projectionId,modelVersion:1,sourceRun:run.id,count,batches,elapsedMs:Date.now()-started};
  }catch(error){
    await source.query('ROLLBACK').catch(()=>{});
    if(created)await target.query(`UPDATE defender_shadow_generations SET state='failed',verified_at=NULL WHERE company_id=$1 AND projection_id=$2`,[companyId,projectionId]).catch(()=>{});
    throw error;
  }finally{
    source.removeListener('error',onDisconnect);target.removeListener('error',onDisconnect);
  }
}
