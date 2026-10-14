// Read-only timing of the actual customer-CVE service SQL against a private restore.
// Usage: node scripts/benchmark-customer-cve.cjs PRIVATE_SOCKET_DIRECTORY
const fs = require('node:fs');
const path = require('node:path');
const pg = require('pg');
const socket = fs.realpathSync(process.argv[2] || '.');
if (!socket.startsWith('/home/codex/vuln-recovery/') || !socket.endsWith('/socket')) throw Error('A private restore socket is required.');
const client = new pg.Client({ host: socket, port: 55483, user: 'codex', database: 'recovery_application',
  application_name: 'vuln2-read-only-cve-benchmark', statement_timeout: 15000, connectionTimeoutMillis: 5000 });
function compact(plan) {
  const nodes=[];
  function visit(p) { nodes.push({type:p['Node Type'],index:p['Index Name'],rows:p['Actual Rows'],removed:p['Rows Removed by Filter'],read:p['Shared Read Blocks'],hit:p['Shared Hit Blocks']});for(const child of p.Plans||[])visit(child); }
  visit(plan.Plan);return{executionMs:plan['Execution Time'],planningMs:plan['Planning Time'],nodes};
}
async function explain(label,sql,params) {
  const start=Date.now();
  try {const r=await client.query('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+sql,params);
    console.log(JSON.stringify({label,elapsedMs:Date.now()-start,...compact(r.rows[0]['QUERY PLAN'][0])}));
  }catch(e){console.log(JSON.stringify({label,elapsedMs:Date.now()-start,errorCode:e.code,error:e.code==='57014'?'15-second statement timeout':'Query failed'}));}
}
(async()=>{
  await client.connect();
  try {
    await client.query("SET default_transaction_read_only=on; SET max_parallel_workers_per_gather=0");
    const isolation=(await client.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
    if(!isolation.data.startsWith('/home/codex/vuln-recovery/') || isolation.listen)throw Error('Restore isolation check failed.');
    const service=fs.readFileSync('lib/customer-cve-service.ts','utf8');
    const spotlight=service.match(/`(SELECT r.company_id,r.raw,r.observed_at[\s\S]*?LIMIT \$3)`/)[1];
    const tickets=service.match(/`(SELECT id,state,review_state,ticket_id,ticket_url,closed[\s\S]*?LIMIT 101)`/)[1];
    const generations=(await client.query('SELECT tenant_key,run_id FROM spotlight_import_current ORDER BY tenant_key')).rows;
    console.log(JSON.stringify({event:'restore-benchmark',generations:generations.length,readOnly:true,tcp:false}));
    let n=0;
    const sampleFile=path.join(path.dirname(socket),'cve-benchmark-private-samples.json');
    const samples=fs.existsSync(sampleFile)?JSON.parse(fs.readFileSync(sampleFile,'utf8')):{};
    for(const generation of generations) {
      const sample=samples[generation.run_id] ?? (await client.query(`SELECT cve FROM spotlight_import_records TABLESAMPLE SYSTEM(0.05)
        WHERE run_id=$1 AND tenant_key=$2 AND company_id=$2 AND status IN ('open','reopen') AND cve IS NOT NULL GROUP BY cve ORDER BY count(*) DESC LIMIT 2`,[generation.run_id,generation.tenant_key])).rows;
      samples[generation.run_id]=sample;
      fs.writeFileSync(sampleFile,JSON.stringify(samples),{mode:0o600});
      for(const {cve} of sample) {
        const label=`sample-${++n}`;
        await explain(label+'-spotlight-first',spotlight,[generation.tenant_key,cve,10001,generation.run_id]);
        await explain(label+'-spotlight-repeat',spotlight,[generation.tenant_key,cve,10001,generation.run_id]);
        await explain(label+'-ticket-refs',tickets,[generation.tenant_key,cve]);
        const start=Date.now();
        const fetched=await client.query(spotlight,[generation.tenant_key,cve,10001,generation.run_id]);
        const completeActions=fetched.rows.filter(({raw})=>Array.isArray(raw?.remediation?.entities) && raw.remediation.entities.some(r=>r.action)).length;
        console.log(JSON.stringify({label:label+'-source-transfer',elapsedMs:Date.now()-start,rows:fetched.rowCount,
          jsonBytes:Buffer.byteLength(JSON.stringify(fetched.rows)),rowsWithRemediationActions:completeActions}));
      }
    }
  }finally{await client.end();}
})().catch(e=>{console.error(e.code || e.message);process.exitCode=1;});
