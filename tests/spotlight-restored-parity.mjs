// Offline audit ONLY against the private restored database. Never loads .env.
// Normal reader retains its 15s limit; this harness gives the aggregate 120s to
// measure its full cost and independently checks it in 2,000-record batches.
import assert from 'node:assert/strict';
import { realpath } from 'node:fs/promises';
import pg from 'pg';
import { loadSpotlightSourceReader } from '../scripts/source-read-model-loader.mjs';
const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const pool=new pg.Pool({host:socket,port:55483,user:'codex',database:'recovery_application',max:1,
  connectionTimeoutMillis:5000,options:'-c default_transaction_read_only=on'});
const create=await loadSpotlightSourceReader();
const ranks=['UNKNOWN','NONE','LOW','MEDIUM','HIGH','CRITICAL'];
const zeros=()=>Object.fromEntries(ranks.map(s=>[s,0]));
try {
  const check=(await pool.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(check.data.startsWith('/home/codex/vuln-recovery/')&&!check.listen);
  const companies=(await pool.query('SELECT tenant_key FROM spotlight_import_current ORDER BY tenant_key')).rows;
  for(const company of companies) {
    const timings=[];
    const diagnostic=create({connect:async()=>{
      const client=await pool.connect();
      return {release:()=>client.release(),query:async(sql,values)=>{
        const start=performance.now();
        const result=await client.query(sql==="SET LOCAL statement_timeout='15s'"?"SET LOCAL statement_timeout='120s'":sql,values);
        if(sql.includes('WITH open_rows')||sql.includes('AS misplaced')) timings.push({query:sql.includes('WITH open_rows')?'aggregate':'integrity',ms:Math.round(performance.now()-start)});
        return result;
      }};
    }});
    console.log(JSON.stringify({phase:'restored-only-long-query-diagnostic',company:company.tenant_key}));
    let result;
    try {
      if(!process.argv.includes('--batch-only')) {
        result=await diagnostic({companyId:company.tenant_key,now:new Date(),staleAfterMs:86400000,limit:100});
        assert.equal(result.state,'available');
        console.log(JSON.stringify({phase:'aggregate-completed',timings,sourceInstances:result.summary.sourceInstances}));
      }
    } catch(error) {
      if(error.code!=='57014') throw error;
      console.log(JSON.stringify({phase:'aggregate-timeout',limitSeconds:120,parityVerified:false}));
    }
    const client=await pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL idle_in_transaction_session_timeout='30s'");
      const pointer=(await client.query('SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1',[company.tenant_key])).rows[0];
      if(result) assert.equal(pointer.run_id,result.generation.id);
      let after='',scanned=0,instances=0,suppressed=0,nonCve=0,unknownSuppression=0;
      const byCve=new Map(),devices=new Map(),severity=zeros(),started=performance.now();
      for(;;) {
        // Exact projection only; no descriptions, hosts, remediations, secrets or raw payloads leave SQL.
        const rows=(await client.query(`SELECT r.source_id,r.cve,r.status,r.company_id,
          v.id,v.cid,v.aid,v.status AS raw_status,v.cve->>'id' AS raw_cve,v.cve->>'severity' AS raw_severity,
          v.cve->'base_score' AS score,v.suppression_info->'is_suppressed' AS suppressed
          FROM (SELECT source_id,cve,status,company_id,raw FROM spotlight_import_records
            WHERE run_id=$1 AND tenant_key=$2 AND source_id>$3 ORDER BY source_id LIMIT 2000) r
          CROSS JOIN LATERAL jsonb_to_record(r.raw) AS v(id text,cid jsonb,aid jsonb,status text,cve jsonb,suppression_info jsonb)
          ORDER BY r.source_id`,[pointer.run_id,company.tenant_key,after])).rows;
        if(!rows.length) break;
        for(const row of rows) {
          assert.equal(row.company_id,company.tenant_key); scanned++;
          if(!['open','reopen'].includes(row.status)) continue;
          if(row.suppressed===true) {suppressed++;continue;}
          if(!/^CVE-\d{4}-\d{4,}$/.test(row.cve)) {nonCve++;continue;}
          assert.equal(row.id,row.source_id); assert.equal(row.raw_cve?.toUpperCase(),row.cve);
          assert.ok(['open','reopen'].includes(row.raw_status?.toLowerCase()));
          assert.ok(typeof row.cid==='string'&&row.cid&&typeof row.aid==='string'&&row.aid);
          const device=JSON.stringify([row.cid,row.aid]);
          if(!devices.has(device)) devices.set(device,devices.size);
          const rating=ranks.includes(row.raw_severity?.toUpperCase())?row.raw_severity.toUpperCase():'UNKNOWN';
          severity[rating]++; instances++; if(row.suppressed!==false) unknownSuppression++;
          const score= typeof row.score==='number'||typeof row.score==='string' ? Number(row.score) : NaN;
          const cvss=row.score!==''&&Number.isFinite(score)&&score>=0&&score<=10?score:null;
          const cve=byCve.get(row.cve)??{cve:row.cve,severity:rating,cvss:null,sourceInstances:0,devices:new Set()};
          if(ranks.indexOf(rating)>ranks.indexOf(cve.severity)) cve.severity=rating;
          if(cvss!==null) cve.cvss=cve.cvss===null?cvss:Math.max(cve.cvss,cvss);
          cve.sourceInstances++; cve.devices.add(devices.get(device)); byCve.set(row.cve,cve);
        }
        after=rows.at(-1).source_id;
        if(scanned%100000===0) console.log(JSON.stringify({phase:'independent-batched-parity',records:scanned,elapsedMs:Math.round(performance.now()-started)}));
        assert.ok(performance.now()-started<300000,'Parity audit exceeded five minutes');
      }
      let pairs=0; const cveSeverity=zeros();
      const cves=[...byCve.values()].map(({devices,...row})=>{pairs+=devices.size;cveSeverity[row.severity]++;return{...row,affectedDevices:devices.size};});
      cves.sort((a,b)=>ranks.indexOf(b.severity)-ranks.indexOf(a.severity)||b.affectedDevices-a.affectedDevices||(a.cve<b.cve?-1:a.cve>b.cve?1:0));
      const summary={sourceInstances:instances,deviceCveFindings:pairs,uniqueCves:byCve.size,affectedDevices:devices.size,
        inventoryDevices:null,unknownSuppressionInstances:unknownSuppression,excludedSuppressedInstances:suppressed,excludedNonCveInstances:nonCve,
        severity:{sourceInstances:severity,uniqueCves:cveSeverity}};
      if(result) {assert.deepEqual(result.summary,summary);assert.deepEqual(result.cves.rows,cves.slice(0,100));}
      await client.query('COMMIT');
      console.log(JSON.stringify({phase:result?'parity-passed':'batch-baseline-only',company:company.tenant_key,scanned,summary,timings,
        batchAuditMs:Math.round(performance.now()-started),peakRssMiB:Math.round(process.resourceUsage().maxRSS/1024),
        normalReaderLimitSeconds:15,diagnosticOnlyLimitSeconds:120}));
    } catch(error) {await client.query('ROLLBACK').catch(()=>{});throw error;} finally {client.release();}
  }
} finally {await pool.end();}
