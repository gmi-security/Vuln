import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID,createHash} from 'node:crypto';
import pg from 'pg';
import {loadReportingSections} from '../scripts/reporting-sections-loader.mjs';
import {buildCustomerReportingSections,readCustomerReportingSections} from '../lib/db/customer-reporting-sections.mjs';
import {company,reportingFixture,expectedReport} from './reporting-sections-fixture.mjs';
globalThis.fetch=()=>{throw Error('No vendor, scan or ticket calls allowed');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const token=randomUUID().replaceAll('-',''),sourceName=`vuln2_reporting_source_test_${token}`,targetName=`vuln2_reporting_test_${token}`;
const admin=new pg.Client({...config,database:'postgres'});let source,target,observer,writer,created=[];let groups=0;
const ok=message=>{groups++;console.log('PASS '+message);};
const {create,reference}=await loadReportingSections();
try{
 await admin.connect();const g=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);
 for(const name of [sourceName,targetName]){await admin.query(`CREATE DATABASE ${name}`);created.push(name);}
 source=new pg.Client({...config,database:sourceName});target=new pg.Client({...config,database:targetName});
 observer=new pg.Client({...config,database:targetName});writer=new pg.Client({...config,database:sourceName});
 await Promise.all([source.connect(),target.connect(),observer.connect(),writer.connect()]);
 await target.query(await readFile('docs/sql/customer-reporting-sections.sql','utf8'));
 await source.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb,updated_at timestamptz DEFAULT now());CREATE TABLE vuln_metrics_history(id bigserial PRIMARY KEY,company_id text,ts timestamptz,data jsonb)');
 const data=reportingFixture(1200),foreign={...company,id:'CO-OTHER',name:'Foreign'};
 await source.query("INSERT INTO vuln_store(key,data) VALUES('meta','{}'),('companies:00',$1)",[JSON.stringify([[company.id,company],[foreign.id,foreign]])]);
 for(const [kind,n] of [['findings',64],['scans',8],['assets',16]]){
  const bucket=id=>createHash('sha1').update(id).digest().readUInt32BE(0)%n;
  data[kind].sort((a,b)=>bucket(a.id)-bucket(b.id));
  for(let i=0;i<n;i++){
   const rows=[...data[kind],{...data[kind][0],id:'FOREIGN',companyId:foreign.id}].filter(r=>bucket(r.id)===i);
   await source.query('INSERT INTO vuln_store(key,data) VALUES($1,$2)',[`${kind}:${String(i).padStart(2,'0')}`,JSON.stringify(rows.map(r=>[r.id,r]))]);
  }
 }
 // Relative dates ensure the fixture continues to exercise the history window.
 for(let i=0;i<data.history.length;i++)data.history[i].ts=new Date(Date.now()-(2-i)*86400000).toISOString();
 for(const row of data.history)await source.query('INSERT INTO vuln_metrics_history(company_id,ts,data) VALUES($1,$2,$3)',[company.id,row.ts,row.data]);
 const read=()=>readCustomerReportingSections(source,observer,company.id);
 const build=options=>buildCustomerReportingSections(source,target,company.id,create,options);
 assert.equal((await read()).state,'not-ready');
 await build();let result=await read();assert.equal(result.state,'available');
 assert.deepEqual(result.model,JSON.parse(JSON.stringify(expectedReport(reference,data))));assert.equal(result.records,1200);
 assert.doesNotMatch(JSON.stringify(result),/FOREIGN/);ok('all-source saved sections match every field of current reporting with exact customer scope');
 const previous=result.snapshotId;
 await assert.rejects(()=>build({beforeCommit:async()=>{
  const old=(await observer.query('SELECT snapshot_id FROM customer_reporting_sections WHERE company_id=$1',[company.id])).rows[0];assert.equal(old.snapshot_id,previous);
  throw Error('Injected reporting failure');}}),/Injected reporting failure/);
 assert.equal((await read()).snapshotId,previous);ok('failed replacement leaves previous complete report visible');
 await build({beforeCommit:async()=>{
  await assert.rejects(()=>buildCustomerReportingSections(writer,observer,company.id,create),/build busy/);
 }});ok('concurrent builder cannot replace a report out of order');
 await writer.query("UPDATE vuln_store SET data=jsonb_set(data,'{0,1,status}','\"Resolved\"') WHERE key='findings:00'");
 assert.equal((await read()).state,'stale');await build();assert.equal((await read()).state,'available');
 await writer.query("INSERT INTO vuln_metrics_history(company_id,ts,data) VALUES($1,now(),'{\"totalOpen\":111}')",[company.id]);
 assert.equal((await read()).state,'stale');await build();
 await writer.query("UPDATE vuln_metrics_history SET data='{\"totalOpen\":222}' WHERE company_id=$1",[company.id]);
 assert.equal((await read()).state,'stale');ok('finding, appended history and edited historical rows invalidate cached output');
 await build({beforeCommit:async()=>{await writer.query("UPDATE vuln_store SET updated_at=now() WHERE key='assets:00'");}});
 assert.equal((await read()).state,'stale');ok('concurrent source commit never presents a mixed or current report');
 await build();await target.query("UPDATE customer_reporting_sections SET captured_at=now()-interval '16 minutes',expires_at=now()-interval '1 minute'");
 assert.equal((await read()).state,'stale');ok('expired saved observations are explicitly stale');
 await build();await writer.query("UPDATE vuln_store SET data=jsonb_set(data,'{0,1,name}','\"Renamed customer\"') WHERE key='companies:00'");
 assert.equal((await read()).state,'stale');await build();assert.equal((await read()).model.company.name,'Renamed customer');
 ok('customer metadata changes invalidate the previous saved report');
 await assert.rejects(()=>readCustomerReportingSections(source,target,'CO-MISSING'),/Known non-demo/);
 await writer.query("UPDATE vuln_store SET data=jsonb_set(data,'{1,1,isDemo}','true') WHERE key='companies:00'");
 await assert.rejects(()=>readCustomerReportingSections(source,target,foreign.id),/Known non-demo/);
 await writer.query("UPDATE vuln_store SET data=jsonb_set(data,'{1,1,isDemo}','\"true\"') WHERE key='companies:00'");
 await assert.rejects(()=>readCustomerReportingSections(source,target,foreign.id),/Known non-demo/);
 ok('unknown and demo customers cannot read saved reports');
 await target.query("UPDATE customer_reporting_sections SET model=jsonb_set(model,'{oversized}',to_jsonb(repeat('x',2200000)))");
 await assert.rejects(()=>read(),/Invalid saved reporting/);await build();ok('oversized stored responses are withheld');
 await target.query("UPDATE customer_reporting_sections SET model=jsonb_set(model,'{metrics,vulnerabilities,open}','0')");
 await assert.rejects(()=>read(),/Invalid saved reporting/);await build();ok('altered saved content fails checksum verification after JSONB round trip');
 const original=(await source.query("SELECT data FROM vuln_store WHERE key='findings:01'")).rows[0].data;
 await source.query("UPDATE vuln_store SET data=data || jsonb_build_array(data->0) WHERE key='findings:01'");
 await assert.rejects(()=>build(),/Invalid or oversized/);
 await source.query("UPDATE vuln_store SET data=$1 WHERE key='findings:01'",[JSON.stringify(original)]);
 await source.query("UPDATE vuln_store SET data=data || jsonb_build_array((SELECT data->0 FROM vuln_store WHERE key='findings:01')) WHERE key='findings:02'");
 await assert.rejects(()=>build(),/wrong bucket/);
 await source.query("UPDATE vuln_store SET data=data - (jsonb_array_length(data)-1) WHERE key='findings:02'");
 ok('duplicate IDs and misplaced shard identities cannot inflate reporting totals');
 await source.query("UPDATE vuln_store SET data=$1 WHERE key='findings:01'",[JSON.stringify([['bad',{id:'mismatch',companyId:company.id}]])]);
 await assert.rejects(()=>build(),/Invalid or oversized reporting bucket/);
 await source.query("UPDATE vuln_store SET data='[]' WHERE key='findings:01'");
 await source.query("UPDATE vuln_store SET data='{\"findings\":[]}' WHERE key='meta'");
 await assert.rejects(()=>build(),/snapshot overrides/);ok('malformed buckets and unsupported meta overrides are rejected without replacing a report');
 console.log(`PASS ${groups} isolated reporting sections groups`);
}finally{
 await Promise.allSettled([source?.end(),target?.end(),observer?.end(),writer?.end()]);
 for(const name of created.reverse())await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();
}
