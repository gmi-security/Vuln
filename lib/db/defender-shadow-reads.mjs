// Offline, derived read model. No application route, source import or publication pointer.
const statuses=['Open','In Remediation','Risk Accepted','False Positive','Resolved'];
const severityNames=['Critical','High','Medium','Low','Info'];
const cvePattern="^CVE-[0-9]{4}-[0-9]{4,19}$";
const endpoint="f.connector NOT IN ('spiderfoot','artemis','burp','zap')";
const open="w.status IN ('Open','In Remediation')";
const join=`FROM defender_shadow_findings f JOIN defender_shadow_workflow w USING(company_id,projection_id,finding_id)
  JOIN defender_shadow_assessments a USING(company_id,projection_id,finding_id)`;
const requireValue=(ok,message)=>{if(!ok)throw new Error(message);};
const scope=(companyId,projectionId)=>requireValue(typeof companyId==='string'&&/^CO-[A-Za-z0-9-]{1,120}$/.test(companyId)&&
  typeof projectionId==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(projectionId),'Explicit projection scope required');

export function shadowReadRequest(request){
  const {companyId,projectionId,view='summary',status='open',limit=50,cursor=null}=request;
  scope(companyId,projectionId);
  requireValue(['summary','findings','cves'].includes(view)&&['open','all',...statuses].includes(status),'Invalid read view or status');
  requireValue(view==='findings'||status==='open','Status filter requires findings view');
  requireValue(Number.isInteger(limit)&&limit>=1&&limit<=100,'Page size must be 1-100');
  let after=0;
  if(cursor!==null){
    requireValue(view!=='summary'&&typeof cursor==='string'&&cursor.length<=1024&&/^[A-Za-z0-9_-]+$/.test(cursor),'Invalid page cursor');
    let parsed;try{parsed=JSON.parse(Buffer.from(cursor,'base64url').toString('utf8'));}catch{throw new Error('Invalid page cursor');}
    requireValue(parsed&&parsed.v===1&&parsed.c===companyId&&parsed.p===projectionId&&parsed.k===view&&parsed.s===status&&
      Number.isInteger(parsed.a)&&parsed.a>0&&parsed.a<=500000,'Page cursor scope or position mismatch');
    after=parsed.a;
  }
  return {companyId,projectionId,view,status,limit,after};
}
export const shadowCursor=(request,position)=>Buffer.from(JSON.stringify({v:1,c:request.companyId,p:request.projectionId,k:request.view,s:request.status,a:position})).toString('base64url');

export function validShadowSummary(s,count){
  const integer=n=>Number.isInteger(n)&&n>=0&&n<=count;
  if(!s||!integer(count)||s.records!==count||!s.bySeverity||!s.endpointByStatus)return false;
  if(!['openRemediation','critical','high','kev','exploitable','cveOpen','openEndpoint','openWeb','openExposure','uniqueOpenCves','affectedDeviceIds','affectedAssetKeys'].every(k=>integer(s[k]))||
    !severityNames.every(k=>integer(s.bySeverity[k]))||!statuses.every(k=>integer(s.endpointByStatus[k])))return false;
  return severityNames.reduce((n,k)=>n+s.bySeverity[k],0)===s.openRemediation&&s.critical===s.bySeverity.Critical&&s.high===s.bySeverity.High&&
    s.openEndpoint+s.openWeb===s.openRemediation&&s.openRemediation+s.openExposure<=count&&
    s.endpointByStatus.Open+s.endpointByStatus['In Remediation']===s.openEndpoint&&statuses.reduce((n,k)=>n+s.endpointByStatus[k],0)<=count&&
    ['kev','exploitable','cveOpen'].every(k=>s[k]<=s.openRemediation)&&['uniqueOpenCves','affectedDeviceIds','affectedAssetKeys'].every(k=>s[k]<=s.openEndpoint);
}

async function generation(client,companyId,projectionId,lock=false){
  const {rows:[row]}=await client.query(`SELECT model_version,state,finding_count,source_run,snapshot_saved_at,verified_at
    FROM defender_shadow_generations WHERE company_id=$1 AND projection_id=$2${lock?' FOR SHARE':''}`,[companyId,projectionId]);
  requireValue(row?.state==='verified'&&row.model_version===2,'Verified version-2 customer projection required');return row;
}

export async function buildDefenderShadowReads(client,companyId,projectionId,{beforeCommit}={}){
  scope(companyId,projectionId);
  const {rows:[guard]}=await client.query("SELECT current_database() db,current_setting('data_directory') dir,current_setting('listen_addresses') listen");
  requireValue(/^vuln2_shadow_test_[a-f0-9]+$/.test(guard.db)&&guard.dir.startsWith('/home/codex/vuln-recovery/')&&!guard.listen,'Disposable shadow target required');
  const start=Date.now();let phase='generation-check';
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
  try{
    await client.query("SET LOCAL statement_timeout='15s';SET LOCAL lock_timeout='2s';SET LOCAL idle_in_transaction_session_timeout='30s'");
    const {rows:[lease]}=await client.query('SELECT pg_try_advisory_xact_lock(hashtextextended($1,804247)) AS acquired',[`${companyId}:${projectionId}`]);
    requireValue(lease.acquired,'Derived shadow build busy');
    const g=await generation(client,companyId,projectionId,true),params=[companyId,projectionId];
    requireValue(g.finding_count<=500000,'Shadow finding limit exceeded');
    const existing=await client.query('SELECT 1 FROM defender_shadow_read_summary WHERE company_id=$1 AND projection_id=$2',params);
    if(existing.rows.length){await client.query('COMMIT');return {alreadyBuilt:true};}
    phase='summary-aggregation';
    const {rows:groups}=await client.query(`SELECT w.status,a.severity,f.connector,count(*)::int n,
      count(*) FILTER(WHERE f.detail->'kev'='true'::jsonb)::int kev,
      count(*) FILTER(WHERE f.detail->'exploitAvailable'='true'::jsonb)::int exploitable,
      count(*) FILTER(WHERE f.issue_key ~* '${cvePattern}')::int cve_findings
      ${join} WHERE f.company_id=$1 AND f.projection_id=$2 GROUP BY w.status,a.severity,f.connector`,params);
    const summary={records:0,openRemediation:0,critical:0,high:0,kev:0,exploitable:0,cveOpen:0,
      bySeverity:Object.fromEntries(severityNames.map(s=>[s,0])),openEndpoint:0,openWeb:0,openExposure:0,
      endpointByStatus:Object.fromEntries(statuses.map(s=>[s,0])),uniqueOpenCves:0,affectedDeviceIds:0,affectedAssetKeys:0};
    for(const row of groups){
      summary.records+=row.n;
      const isEndpoint=!['spiderfoot','artemis','burp','zap'].includes(row.connector),isOpen=['Open','In Remediation'].includes(row.status);
      if(isEndpoint)summary.endpointByStatus[row.status]+=row.n;
      if(!isOpen)continue;
      if(['spiderfoot','artemis'].includes(row.connector)){summary.openExposure+=row.n;continue;}
      summary.openRemediation+=row.n;summary.bySeverity[row.severity]+=row.n;summary.kev+=row.kev;summary.exploitable+=row.exploitable;summary.cveOpen+=row.cve_findings;
      if(isEndpoint)summary.openEndpoint+=row.n;else summary.openWeb+=row.n;
    }
    summary.critical=summary.bySeverity.Critical;summary.high=summary.bySeverity.High;
    requireValue(summary.records===g.finding_count,'Normalized record count mismatch');
    phase='priority-sort';
    await client.query(`CREATE TEMP TABLE defender_shadow_priority_stage ON COMMIT DROP AS
      SELECT row_number() OVER(ORDER BY a.real_risk DESC,a.cvss DESC,f.legacy_order)::int AS position,f.finding_id,w.status
      ${join} WHERE f.company_id=$1 AND f.projection_id=$2 AND ${endpoint}`,params);
    await client.query('CREATE UNIQUE INDEX ON defender_shadow_priority_stage(position)');
    phase='priority-insert';
    const endpointCount=Object.values(summary.endpointByStatus).reduce((n,v)=>n+v,0);let written=0;
    for(let after=0;after<endpointCount;after+=5000){
      requireValue(Date.now()-start<90000,'Derived shadow build deadline exceeded');
      const inserted=await client.query(`INSERT INTO defender_shadow_priority SELECT $1,$2,position,finding_id,status
        FROM defender_shadow_priority_stage WHERE position>$3 AND position<=$4 ORDER BY position`,[...params,after,after+5000]);
      written+=inserted.rowCount;
    }
    requireValue(written===endpointCount,'Priority index count mismatch');
    phase='cve-build';
    await client.query(`INSERT INTO defender_shadow_cve_pages
      WITH grouped AS (SELECT f.issue_key AS cve,
        max(CASE a.severity WHEN 'Critical' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 2 ELSE 1 END) AS rank,
        count(DISTINCT e.device_id)::int devices,count(*)::int findings,max(a.cvss) cvss,max(a.real_risk) risk
        ${join} JOIN defender_shadow_evidence e USING(company_id,projection_id,finding_id)
        WHERE f.company_id=$1 AND f.projection_id=$2 AND ${endpoint} AND ${open} AND f.issue_key ~* '${cvePattern}' GROUP BY f.issue_key)
      SELECT $1,$2,row_number() OVER(ORDER BY rank DESC,devices DESC,cve COLLATE "C")::int,cve,
        (ARRAY['Info','Low','Medium','High','Critical'])[rank],devices,findings,cvss,risk FROM grouped`,params);
    phase='identity-counts';
    const {rows:[counts]}=await client.query(`SELECT count(*)::int cves,COALESCE(sum(findings),0)::int findings FROM defender_shadow_cve_pages WHERE company_id=$1 AND projection_id=$2`,params);
    summary.uniqueOpenCves=counts.cves;
    const {rows:[identities]}=await client.query(`SELECT count(DISTINCT e.device_id)::int devices,count(DISTINCT f.asset_key)::int assets,
      count(*) FILTER(WHERE f.issue_key ~* '${cvePattern}')::int cve_findings ${join}
      JOIN defender_shadow_evidence e USING(company_id,projection_id,finding_id)
      WHERE f.company_id=$1 AND f.projection_id=$2 AND ${endpoint} AND ${open}`,params);
    requireValue(identities.cve_findings===counts.findings,'CVE aggregation count mismatch');
    summary.affectedDeviceIds=identities.devices;summary.affectedAssetKeys=identities.assets;
    requireValue(validShadowSummary(summary,g.finding_count),'Derived summary validation failed');
    phase='publish-summary';
    await client.query('INSERT INTO defender_shadow_read_summary(company_id,projection_id,read_version,finding_count,summary) VALUES($1,$2,1,$3,$4)',[...params,g.finding_count,summary]);
    await beforeCommit?.();
    requireValue(Date.now()-start<90000,'Derived shadow build deadline exceeded');
    await client.query('COMMIT');return {alreadyBuilt:false,summary,elapsedMs:Date.now()-start};
  }catch(error){error.auditPhase=phase;await client.query('ROLLBACK').catch(()=>{});throw error;}
}

export const MAX_SHADOW_PAGE_BYTES=8*1024*1024;
async function boundedPage(client,sql,params){
  const {rows:[size]}=await client.query(`SELECT COALESCE(sum(octet_length(row_to_json(bounded)::text)),0)::text bytes FROM (${sql}) bounded`,params);
  if(Number(size.bytes)>MAX_SHADOW_PAGE_BYTES)throw Object.assign(new Error('Saved comparison page exceeds 8 MiB; no partial result'),{status:413});
  return client.query(sql,params);
}
export async function readDefenderShadow(client,request){
  const r=shadowReadRequest(request),params=[r.companyId,r.projectionId];
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='5s';SET LOCAL idle_in_transaction_session_timeout='15s'");
    const g=await generation(client,...params);
    const {rows:[saved]}=await client.query('SELECT read_version,finding_count,summary,built_at FROM defender_shadow_read_summary WHERE company_id=$1 AND projection_id=$2',params);
    if(!saved){await client.query('COMMIT');return {state:'not-ready',companyId:r.companyId,projectionId:r.projectionId,scope:'published-defender-cohort'};}
    requireValue(saved.read_version===1&&saved.finding_count===g.finding_count&&validShadowSummary(saved.summary,g.finding_count),'Saved summary mismatch');
    let rows=[],total=0;
    if(r.view==='findings'){
      const filter=r.status==='open'?"AND status IN ('Open','In Remediation')":r.status==='all'?'':'AND status=$5';
      const values=[...params,r.after,r.limit+1];if(!['open','all'].includes(r.status))values.push(r.status);
      const page=await boundedPage(client,`WITH page AS MATERIALIZED (SELECT position,finding_id,status FROM defender_shadow_priority
        WHERE company_id=$1 AND projection_id=$2 AND position>$3 ${filter} ORDER BY position LIMIT $4)
        SELECT p.position,f.finding_id AS id,f.issue_key AS cve,f.asset_key AS asset,f.detail->>'title' AS title,
          a.severity,a.real_risk AS "realRisk",a.cvss,p.status,w.last_seen AS "lastSeen",
          CASE WHEN jsonb_typeof(f.detail->'seenBy')='array' AND jsonb_array_length(f.detail->'seenBy')>0 THEN f.detail->'seenBy' ELSE jsonb_build_array(f.connector) END AS connectors
        FROM page p JOIN LATERAL(SELECT * FROM defender_shadow_findings WHERE company_id=$1 AND projection_id=$2 AND finding_id=p.finding_id OFFSET 0) f ON true
        JOIN LATERAL(SELECT * FROM defender_shadow_assessments WHERE company_id=$1 AND projection_id=$2 AND finding_id=p.finding_id OFFSET 0) a ON true
        JOIN LATERAL(SELECT last_seen FROM defender_shadow_workflow WHERE company_id=$1 AND projection_id=$2 AND finding_id=p.finding_id OFFSET 0) w ON true ORDER BY p.position`,values);
      rows=page.rows;total=r.status==='open'?saved.summary.openEndpoint:r.status==='all'?Object.values(saved.summary.endpointByStatus).reduce((a,b)=>a+b,0):saved.summary.endpointByStatus[r.status];
    }else if(r.view==='cves'){
      rows=(await boundedPage(client,`SELECT position,cve,severity,affected_devices AS "affectedDevices",findings,cvss,real_risk AS "realRisk"
        FROM defender_shadow_cve_pages WHERE company_id=$1 AND projection_id=$2 AND position>$3 ORDER BY position LIMIT $4`,[...params,r.after,r.limit+1])).rows;
      total=saved.summary.uniqueOpenCves;
    }
    const more=rows.length>r.limit;rows=rows.slice(0,r.limit);
    const next=more?shadowCursor(r,rows.at(-1).position):null;
    await client.query('COMMIT');
    return {state:'available',companyId:r.companyId,projectionId:r.projectionId,scope:'published-defender-cohort',projectionModelVersion:2,readModelVersion:1,sourceRun:g.source_run,
      snapshotSavedAt:g.snapshot_saved_at,builtAt:saved.built_at,summary:saved.summary,
      page:r.view==='summary'?null:{total,rows:rows.map(({position,...row})=>row),nextCursor:next}};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}
