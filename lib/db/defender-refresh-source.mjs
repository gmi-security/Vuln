// Explicit completed-import reader for offline refresh candidates. SELECT only;
// no schema initializer, API calls, credentials or runtime store dependency.
const requireValue=(value,message)=>{if(!value)throw Error(message);};
export async function readDefenderRefreshSource(client,companyId,{afterSelected,deadlineMs=120000,inTransaction=false}={}){
  requireValue(typeof companyId==='string'&&/^CO-[A-Za-z0-9-]+$/.test(companyId),'Explicit customer required');
  requireValue(Number.isInteger(deadlineMs)&&deadlineMs>0&&deadlineMs<=300000,'Invalid source read deadline');
  const started=Date.now(),check=()=>requireValue(Date.now()-started<deadlineMs,'Source read deadline exceeded');
  if(inTransaction){
    const {rows:[state]}=await client.query("SELECT current_setting('transaction_isolation') isolation,current_setting('transaction_read_only') readonly");
    requireValue(state.isolation==='repeatable read'&&state.readonly==='on','Pinned read-only transaction required');
  }else await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='15s';SET LOCAL idle_in_transaction_session_timeout='60s'");
    const {rows:[run]}=await client.query(`SELECT c.current_run::text id,c.revision,c.last_success_at,r.summary,
      r.status,r.revision run_revision,r.finished_at FROM defender_connections c
      JOIN defender_import_runs r ON r.id=c.current_run AND r.company_id=c.company_id WHERE c.company_id=$1`,[companyId]);
    requireValue(run?.status==='succeeded'&&run.revision===run.run_revision&&run.finished_at&&run.last_success_at,'Complete matching source generation required');
    await afterSelected?.(run.id);
    const {rows:[count]}=await client.query(`SELECT count(*)::int findings,coalesce(sum(octet_length(record::text)),0)::text bytes FROM defender_records WHERE run_id=$1`,[run.id]);
    const {rows:[inventory]}=await client.query(`SELECT count(*)::int devices,coalesce(sum(octet_length(record::text)),0)::text bytes FROM defender_devices WHERE run_id=$1`,[run.id]);
    requireValue(count.findings===run.summary?.findings&&inventory.devices===run.summary?.inventoryDevices,'Retained source counts differ from completed summary');
    requireValue(count.findings<=1000000&&inventory.devices<=100000&&Number(count.bytes)+Number(inventory.bytes)<=512*1024*1024,'Offline source input limit exceeded');
    const devices=(await client.query('SELECT device_id,record FROM defender_devices WHERE run_id=$1 ORDER BY device_id',[run.id])).rows;
    requireValue(devices.every(d=>d.record?.deviceId===d.device_id),'Source device identity mismatch');
    const findings=[];let device='',cve='';
    for(;;){
      check();
      // Match createDefenderStore.platformSnapshot device/CVE aggregation.
      const {rows}=await client.query(`SELECT device_id AS "deviceId",cve,MAX(record->>'hostname') AS hostname,
        (ARRAY['UNKNOWN','NONE','LOW','MEDIUM','HIGH','CRITICAL'])[MAX(CASE severity WHEN 'CRITICAL' THEN 6 WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 4 WHEN 'LOW' THEN 3 WHEN 'NONE' THEN 2 ELSE 1 END)] AS severity,
        MAX(cvss) AS cvss,MIN(record->>'firstSeen') AS "firstSeen",MAX(record->>'lastSeen') AS "lastSeen",
        BOOL_OR(record->>'exploitability' IN ('ExploitIsPublic','ExploitIsVerified','ExploitIsInKit')) AS "exploitAvailable",
        STRING_AGG(DISTINCT CONCAT_WS(' · ',NULLIF(record->>'softwareName',''),NULLIF(record->>'softwareVersion',''),record->>'remediation',NULLIF(record->>'remediationId','')), E'\n') AS remediation
        FROM defender_records WHERE run_id=$1 AND (device_id,cve)>($2,$3)
        GROUP BY device_id,cve ORDER BY device_id,cve LIMIT 2000`,[run.id,device,cve]);
      findings.push(...rows);requireValue(findings.length<=500000,'Offline source finding limit exceeded');
      if(rows.length<2000)break;
      device=rows.at(-1).deviceId;cve=rows.at(-1).cve;
    }
    check();if(!inTransaction)await client.query('COMMIT');
    return {revision:run.revision,snapshot:{companyId,runId:run.id,observedAt:new Date(run.last_success_at).toISOString(),devices:devices.map(d=>d.record),findings}};
  }catch(error){if(!inTransaction)await client.query('ROLLBACK').catch(()=>{});throw error;}
}
