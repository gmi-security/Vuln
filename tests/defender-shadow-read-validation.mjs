// Independent expected results from real reporting functions and source snapshot records.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule} from 'node:vm';
import ts from 'typescript';
import {buildDefenderShadowReads,readDefenderShadow} from '../lib/db/defender-shadow-reads.mjs';
const modules=new Map();
for(const name of ['reporting-customer-model','reporting-metrics','reporting-source-activity']){
  const code=ts.transpileModule(await readFile(`lib/${name}.ts`,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  modules.set(name,new SourceTextModule(code));
}
const model=modules.get('reporting-customer-model');
await model.link(spec=>{const mod=modules.get(spec.replace('./',''));assert.ok(mod,'Unexpected reporting dependency');return mod;});await model.evaluate();
const ranks=['Info','Low','Medium','High','Critical'];
const endpoint=f=>!['burp','zap','spiderfoot','artemis'].includes(f.connector);
const isOpen=f=>['Open','In Remediation'].includes(f.status);
const sort=(a,b)=>b.realRisk-a.realRisk||b.cvss-a.cvss;

export async function savedReference(source,companyId){
  const records=[];await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    for(let i=0;i<64;i++){
      const {rows}=await source.query(`SELECT jsonb_build_object('id',f->'id','companyId',f->'companyId','cve',f->'cve','asset',f->'asset',
        'title',f->'title','status',f->'status','severity',f->'severity','realRisk',f->'realRisk','cvss',f->'cvss','connector',f->'connector',
        'lastSeen',f->'lastSeen','seenBy',f->'seenBy','kev',f->'kev','exploitAvailable',f->'exploitAvailable','defender',jsonb_build_object('deviceId',f->'defender'->'deviceId')) AS record
        FROM vuln_store,LATERAL jsonb_array_elements(data) WITH ORDINALITY AS x(entry,n),LATERAL(SELECT entry->1 AS f) y
        WHERE key=$1 AND f->>'companyId'=$2 AND (f ? 'defender' OR f->>'connector'='defender') ORDER BY n`,[`findings:${String(i).padStart(2,'0')}`,companyId]);
      records.push(...rows.map(r=>r.record));assert.ok(records.length<=500000);
    }
    await source.query('ROLLBACK');return records;
  }catch(error){await source.query('ROLLBACK');throw error;}
}

export async function verifyShadowReads(client,result,records,{failure=false,observer=null,reader=readDefenderShadow,afterBuild}={}){
  const request={companyId:result.companyId,projectionId:result.projectionId};
  assert.equal((await readDefenderShadow(client,request)).state,'not-ready');
  if(failure){
    await assert.rejects(()=>buildDefenderShadowReads(client,result.companyId,result.projectionId,{async beforeCommit(){
      if(observer)assert.equal((await readDefenderShadow(observer,request)).state,'not-ready');
      throw new Error('Injected derived failure');
    }}),/Injected derived failure/);
    assert.equal((await readDefenderShadow(client,request)).state,'not-ready');
    for(const table of ['priority','cve_pages','read_summary'])assert.equal((await client.query(`SELECT count(*)::int n FROM defender_shadow_${table} WHERE company_id=$1 AND projection_id=$2`,[result.companyId,result.projectionId])).rows[0].n,0);
  }
  const built=await buildDefenderShadowReads(client,result.companyId,result.projectionId);
  assert.equal((await buildDefenderShadowReads(client,result.companyId,result.projectionId)).alreadyBuilt,true);
  await afterBuild?.();
  const timings=[];let response;
  for(let i=0;i<3;i++){const start=performance.now();response=await reader(client,request);timings.push(Math.round((performance.now()-start)*10)/10);}
  const expected=model.namespace.buildCustomerReportingModel({id:result.companyId,name:'Private comparison'},records,[],[],[]);
  const metrics=expected.metrics.vulnerabilities,s=response.summary;
  assert.equal(s.records,records.length);for(const key of ['critical','high','kev','exploitable','cveOpen','bySeverity'])assert.deepEqual(s[key],metrics[key]);
  assert.equal(s.openRemediation,metrics.open);assert.equal(s.openWeb,expected.metrics.webTesting.open);assert.equal(s.openExposure,expected.metrics.attackSurface.open);
  assert.equal(s.openEndpoint,expected.priorityTotal);
  const sorted=records.filter(endpoint).sort(sort);
  const pageTimes=[];
  for(const status of ['all','open',...(records.length<2000?['Risk Accepted','Resolved','False Positive','In Remediation']:[])]){
    const wanted=sorted.filter(f=>status==='all'||(status==='open'?isOpen(f):f.status===status));
    let cursor=null,offset=0;
    do{
      const start=performance.now();const page=await reader(client,{...request,view:'findings',status,limit:100,cursor});
      if(pageTimes.length<6)pageTimes.push(Math.round((performance.now()-start)*10)/10);
      assert.equal(page.page.total,wanted.length);
      assert.deepEqual(page.page.rows.map(r=>r.id),wanted.slice(offset,offset+100).map(r=>r.id));
      if(status==='open'&&offset===0){
        assert.deepEqual(page.page.rows.slice(0,25).map(({cvss,...row})=>row),expected.priorityRows);
      }
      offset+=page.page.rows.length;cursor=page.page.nextCursor;
      assert.ok(offset<=wanted.length);
    }while(cursor);
    assert.equal(offset,wanted.length);
  }
  const groups=new Map(),devices=new Set(),assets=new Set();
  for(const f of sorted.filter(isOpen)){
    devices.add(f.defender.deviceId);assets.add(f.asset);
    if(!/^CVE-\d{4}-\d{4,19}$/i.test(f.cve))continue;
    const g=groups.get(f.cve)??{cve:f.cve,severity:'Info',devices:new Set(),findings:0,cvss:0,realRisk:0};
    if(ranks.indexOf(f.severity)>ranks.indexOf(g.severity))g.severity=f.severity;
    g.devices.add(f.defender.deviceId);g.findings++;g.cvss=Math.max(g.cvss,f.cvss);g.realRisk=Math.max(g.realRisk,f.realRisk);groups.set(f.cve,g);
  }
  const cves=[...groups.values()].map(({devices,...g})=>({...g,affectedDevices:devices.size})).sort((a,b)=>ranks.indexOf(b.severity)-ranks.indexOf(a.severity)||b.affectedDevices-a.affectedDevices||(a.cve<b.cve?-1:a.cve>b.cve?1:0));
  assert.equal(s.uniqueOpenCves,cves.length);assert.equal(s.affectedDeviceIds,devices.size);assert.equal(s.affectedAssetKeys,assets.size);
  let cursor=null,offset=0;const cveTimes=[];
  do{const start=performance.now();const page=await reader(client,{...request,view:'cves',limit:100,cursor});
    if(cveTimes.length<3)cveTimes.push(Math.round((performance.now()-start)*10)/10);
    assert.deepEqual(page.page.rows,cves.slice(offset,offset+100));assert.equal(page.page.total,cves.length);
    offset+=page.page.rows.length;cursor=page.page.nextCursor;
  }while(cursor);
  assert.equal(offset,cves.length);
  await assert.rejects(()=>readDefenderShadow(client,{...request,companyId:'CO-OTHER'}),/Verified version-2/);
  if(failure){
    await client.query("UPDATE defender_shadow_read_summary SET summary=jsonb_set(summary,'{openEndpoint}','999999'::jsonb) WHERE company_id=$1 AND projection_id=$2",[result.companyId,result.projectionId]);
    await assert.rejects(()=>readDefenderShadow(client,request),/Saved summary mismatch/);
    await client.query('UPDATE defender_shadow_read_summary SET summary=$3 WHERE company_id=$1 AND projection_id=$2',[result.companyId,result.projectionId,s]);
  }
  if(observer){
    let removed=false;
    const interleaved={async query(sql,params){const value=await client.query(sql,params);
      if(!removed&&sql.startsWith('SELECT model_version,state')){
        removed=true;await observer.query('DELETE FROM defender_shadow_generations WHERE company_id=$1 AND projection_id=$2',[result.companyId,result.projectionId]);
      }return value;}};
    const consistent=await readDefenderShadow(interleaved,{...request,view:'cves'});
    assert.equal(consistent.state,'available');assert.equal(consistent.page.total,cves.length);
    await assert.rejects(()=>readDefenderShadow(client,request),/Verified version-2/);
  }
  return {records:records.length,open:metrics.open,cves:cves.length,buildMs:built.elapsedMs,summaryReadMs:timings,findingPageMs:pageTimes,cvePageMs:cveTimes};
}
