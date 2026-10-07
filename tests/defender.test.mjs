// node --experimental-vm-modules --test --test-force-exit tests/defender.test.mjs
// DEFENDER_TEST_DATABASE_URL must point to a disposable localhost PostgreSQL database.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import { randomUUID, randomBytes } from "node:crypto";
import ts from "typescript";
import pg from "pg";

const modules = new Map();
async function load(path) {
  path = resolve(path);
  if (modules.has(path)) return modules.get(path);
  const source = await readFile(path,"utf8");
  const module = new SourceTextModule(ts.transpileModule(source,{ compilerOptions:{ target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext } }).outputText,{ identifier:path });
  modules.set(path,module);
  await module.link(async specifier => {
    if (specifier === "./persist") return new SyntheticModule(["applicationDatabase"],function() { this.setExport("applicationDatabase",()=>null); });
    if (specifier.startsWith(".")) return load(resolve(dirname(path),specifier+".ts"));
    const values = await import(specifier);
    return new SyntheticModule(Object.keys(values),function() { for (const key of Object.keys(values)) this.setExport(key,values[key]); });
  });
  return module;
}
const clientModule = await load("lib/defender-client.ts"); await clientModule.evaluate();
const storeModule = await load("lib/defender-store.ts"); await storeModule.evaluate();
const module = await load("lib/defender-worker.ts"); await module.evaluate();
const worker = module.namespace;
const client = (await load("lib/defender-client.ts")).namespace;
const { createDefenderStore } = (await load("lib/defender-store.ts")).namespace;
process.env.NEXTAUTH_SECRET = randomBytes(32).toString("hex");
const credentials = { tenantId:randomUUID(),clientId:randomUUID(),clientSecret:"test-secret-not-a-real-key" };
const raw = (overrides={}) => ({ deviceId:"device-A",deviceName:"workstation",cveId:"CVE-2026-12345",cvssScore:9.8,
  softwareVendor:"Vendor",softwareName:"Browser",softwareVersion:"1",vulnerabilitySeverityLevel:"Critical",
  recommendedSecurityUpdate:"Upgrade Browser",recommendedSecurityUpdateId:"KB123",recommendationReference:"recommendation-1",
  firstSeenTimestamp:"2026-10-01 00:00:00",lastSeenTimestamp:"2026-10-07T01:00:00Z",...overrides });
const response = (body,status=200,headers={}) => new Response(JSON.stringify(body),{ status,headers });

test("documented export fields preserve device identity, CVSS and remediation per software version",()=> {
  const a = client.normalizeDefenderRecord(raw()), b = client.normalizeDefenderRecord(raw({ softwareVersion:"2" }));
  assert.equal(a.deviceId,"device-A"); assert.equal(a.cvss,9.8); assert.notEqual(a.sourceId,b.sourceId);
  assert.equal(a.remediationId,"KB123"); assert.equal(a.firstSeen,"2026-10-01T00:00:00.000Z");
  assert.equal(client.normalizeDefenderRecord(raw({ cveId:null })),null);
  assert.equal(client.normalizeDefenderRecord(raw({ cvssScore:undefined })).cvss,null);
  assert.throws(()=>client.normalizeDefenderRecord(raw({ deviceId:undefined })),/device ID/);
});
test("credentials are authenticated encryption and reject tampering and invalid IDs",()=> {
  const sealed = client.sealDefender(credentials);
  assert.ok(!sealed.includes(credentials.clientSecret)); assert.deepEqual(client.openDefender(sealed),credentials);
  const parts=sealed.split("."); parts[2]=Buffer.alloc(16).toString("base64");
  assert.throws(()=>client.openDefender(parts.join(".")),/cannot be opened/);
  assert.throws(()=>client.validateCredentials({...credentials,tenantId:"../common"}),/valid tenant/);
});
test("vulnerability pagination follows all pages and refuses bearer-token exfiltration",async()=> {
  const urls=[];
  const api=client.createDefenderClient(credentials,async(url,init)=> {
    urls.push(url);
    if (url.includes("oauth2")) { assert.match(init.body.get("scope"),/securitycenter/); return response({access_token:"bearer",expires_in:3600}); }
    return response({value:[raw()],...(url.includes("skiptoken") ? {} : {"@odata.nextLink":"https://api.security.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine?skiptoken=2"})});
  });
  const pages=[]; for await (const page of api.batches("findings")) pages.push(page);
  assert.equal(pages.length,2); assert.equal(urls.length,3);
  for(const url of ["https://evil.example/api/machines","https://api.security.microsoft.com/api/other","https://user:pass@api.security.microsoft.com/api/machines"]) assert.throws(()=>client.safeDefenderUrl(url,"/api/machines"),/unexpected/);
});
test("repeated pagination fails closed and device API walks explicit skip pages",async()=> {
  const repeated=client.createDefenderClient(credentials,async url=>url.includes("oauth2")?response({access_token:"token"}):response({value:[raw()],"@odata.nextLink":"https://api.security.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=1000"}));
  await assert.rejects(async()=>{ for await(const page of repeated.batches("findings")) void page; },/pagination did not complete/);
  const urls=[];
  const api=client.createDefenderClient(credentials,async url=> {
    if(url.includes("oauth2"))return response({access_token:"token"});
    urls.push(url);return response({value:url.includes("skip=0")?Array.from({length:1000},(_,i)=>({id:String(i)})):[{id:"1001"}]});
  });
  let count=0;for await(const page of api.batches("devices"))count+=page.length;
  assert.equal(count,1001);assert.ok(urls[1].includes("skip=1000"));
});
test("vulnerability import does not silently truncate at the old 200-page boundary",async()=> {
  let requests=0;
  const api=client.createDefenderClient(credentials,async url=>{
    if(url.includes("oauth2"))return response({access_token:"token"});
    requests++;
    return response({value:[raw({deviceId:`device-${requests}`})],...(requests<202?{"@odata.nextLink":`https://api.security.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine?skiptoken=${requests}`}:{})});
  });
  let count=0;for await(const page of api.batches("findings"))count+=page.length;
  assert.equal(count,202);assert.equal(requests,202);
});
test("rate limits back off; expired tokens renew; API errors never echo response secrets",async()=> {
  let tokens=0,calls=0;const delays=[];
  const api=client.createDefenderClient(credentials,async url=>{
    if(url.includes("oauth2")){tokens++;return response({access_token:`token-${tokens}`});}
    calls++;if(calls===1)return response({},401);if(calls===2)return response({},429,{"retry-after":"2"});
    return response({value:[]});
  },async ms=>{delays.push(ms);});
  for await(const page of api.batches("findings"))void page;
  assert.equal(tokens,2);assert.deepEqual(delays,[2000]);
  const bad=client.createDefenderClient(credentials,async url=>url.includes("oauth2")?response({access_token:"sensitive-token"}):response({error:credentials.clientSecret},403));
  await assert.rejects(()=>bad.test(),err=>err.message.includes("device inventory") && !err.message.includes(credentials.clientSecret));
});
test("incomplete import never publishes a new generation",async()=> {
  let published=false,failed="",stored=0;
  const store={ connection:async()=>({revision:1}),credentials:async()=>credentials,writeDevices:async()=>{},writeRecords:async()=>{stored++;},finish:async()=>{published=true;},fail:async(id,error)=>{failed=error;} };
  const factory=()=>({async *batches(kind){if(kind==="devices"){yield [{id:"device-A"}];return;} yield [raw()];throw new client.DefenderError("Page two failed");}});
  await worker.importDefenderRun({id:"run",company_id:"customer",revision:1},store,factory);
  assert.equal(stored,1);assert.equal(published,false);assert.equal(failed,"Page two failed");
});

test("Defender HTTP gate requires a session, same-origin writes and an existing customer",async()=> {
  let session=null;
  class DashboardError extends Error {}
  const values={
    "next-auth":{getServerSession:async()=>session},"./auth":{authOptions:{}},"./elastic-dashboard":{DashboardError},
    "./elastic-dashboard-http":{dashboardBody:async request=>request.json(),dashboardJson:(body,status=200)=>response(body,status)},
    "./defender-client":{DefenderError:client.DefenderError},
    "./store":{ensureHydrated:async()=>{},getCompany:id=>id==="customer-A"?{id}:undefined},
  };
  const code=ts.transpileModule(await readFile("lib/defender-http.ts","utf8"),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const http=new SourceTextModule(code);
  await http.link(async name=>new SyntheticModule(Object.keys(values[name]),function(){for(const [key,value] of Object.entries(values[name]))this.setExport(key,value);}));
  await http.evaluate();
  const h=http.namespace;
  const request=new Request("http://localhost:3108/api/defender/connections",{method:"POST",headers:{origin:"http://localhost:3108"}});
  const oldUrl=process.env.NEXTAUTH_URL;process.env.NEXTAUTH_URL="http://localhost:3108";
  try {
    await assert.rejects(()=>h.defenderAccess(request,true),err=>err.status===401);
    session={user:{login:"tester",orgMember:true}};
    assert.equal(await h.defenderAccess(request,true),"tester");
    await assert.rejects(()=>h.defenderAccess(new Request(request.url,{method:"POST",headers:{origin:"https://elsewhere.example"}}),true),err=>err.status===403);
    session={user:{login:"removed",orgMember:false}};
    await assert.rejects(()=>h.defenderAccess(request),err=>err.status===401);
    assert.equal(await h.defenderCompany("customer-A"),"customer-A");
    await assert.rejects(()=>h.defenderCompany("does-not-exist"),err=>err.status===404);
    const failure=await h.defenderFailure(new Error("postgres://secret-private-password")).json();
    assert.ok(!JSON.stringify(failure).includes("private-password"));
  } finally { if(oldUrl===undefined)delete process.env.NEXTAUTH_URL;else process.env.NEXTAUTH_URL=oldUrl; }
});

test("PostgreSQL: customer isolation, complete publication, duplicates, leases and daily snapshots",{skip:!process.env.DEFENDER_TEST_DATABASE_URL},async t=> {
  const url=new URL(process.env.DEFENDER_TEST_DATABASE_URL);
  assert.ok(["localhost","127.0.0.1"].includes(url.hostname),"Only a disposable local database is allowed");
  const db=new pg.Pool({connectionString:url.toString()});const store=createDefenderStore(db);
  const companyA=`test-A-${randomUUID()}`,companyB=`test-B-${randomUUID()}`;
  try {
    await store.save({...credentials,companyId:companyA,daily:true},"test");
    await store.save({...credentials,tenantId:randomUUID(),companyId:companyB,daily:false},"test");
    await t.test("connection reads never expose ciphertext or secret; daily waits for manual baseline",async()=>{
      const list=await store.list(companyA);assert.equal(list.length,1);assert.equal(list[0].hasSecret,true);
      assert.ok(!JSON.stringify(list).includes(credentials.clientSecret));assert.equal(list[0].secret,undefined);
      await store.schedule();assert.equal(await store.claim(),null);
      await assert.rejects(()=>store.credentials(companyA,{clientId:randomUUID()}),/secret again/);
    });
    const id=await store.enqueue(companyA,"test"); assert.equal(await store.enqueue(companyA,"test"),id);
    const run=await store.claim(); assert.equal(run.id,id);assert.equal(await store.claim(),null);
    await t.test("edits cannot race active imports",async()=>{
      await assert.rejects(()=>store.save({...credentials,companyId:companyA,daily:false},"test"),/finish/);
    });
    await store.writeDevices(id,[{id:"device-A",computerDnsName:"same-name",lastIpAddress:"10.0.0.1"},{id:"device-B",computerDnsName:"same-name",lastIpAddress:"10.0.0.1"}]);
    const rows=[raw(),raw({softwareVersion:"2"}),raw({deviceId:"device-B"}),raw({deviceId:"device-B",cveId:"CVE-2026-22222",vulnerabilitySeverityLevel:"High"})].map(client.normalizeDefenderRecord);
    await store.writeRecords(id,[...rows,rows[0]],5,0);
    await t.test("partial rows stay invisible until atomic publication",async()=>{
      assert.equal((await store.results(companyA,"cves",0)).summary,null);
    });
    await store.finish(run);
    await t.test("software rows and shared IP devices remain distinct; CVEs aggregate",async()=>{
      const result=await store.results(companyA,"cves",0);
      assert.equal(result.summary.findings,4);assert.equal(result.summary.cves,2);assert.equal(result.summary.affectedDevices,2);
      assert.equal(result.rows[0].cve,"CVE-2026-12345");assert.equal(result.rows[0].devices,2);assert.equal(result.rows[0].findings,3);
      assert.equal((await store.results(companyB,"cves",0)).summary,null);
      assert.equal((await store.results(companyA,"findings",0,"CVE-2026-12345")).rows.length,3);
      assert.equal((await store.results(companyA,"devices",0)).total,2);
      const snapshot=await store.platformSnapshot(companyA);
      assert.equal(snapshot.runId,id);assert.equal(snapshot.findings.length,3);
      assert.equal(snapshot.devices.length,2);assert.match(snapshot.findings[0].remediation,/Browser/);
      assert.equal(await store.platformSnapshot(companyB),null);
    });
    await t.test("tenant cannot be reassigned after baseline; failed refresh preserves current",async()=>{
      await assert.rejects(()=>store.save({...credentials,tenantId:randomUUID(),companyId:companyA,daily:true},"test"),/migration/);
      const next=await store.enqueue(companyA,"test");await store.claim();await store.fail(next,"failed page");
      assert.equal((await store.results(companyA,"cves",0)).summary.findings,4);
    });
    await t.test("expired worker cannot write or publish; new import can be queued",async()=>{
      const next=await store.enqueue(companyA,"test");const claimed=await store.claim();
      await db.query("UPDATE defender_import_runs SET lease_until=now()-interval '1 second' WHERE id=$1",[next]);
      await store.claim();await assert.rejects(()=>store.writeRecords(next,rows,4,0),/lease expired/);
      await assert.rejects(()=>store.finish(claimed),/lease expired/);
      assert.equal((await store.results(companyA,"cves",0)).summary.findings,4);
    });
    await t.test("complete empty snapshot shows zero; history has one UTC observation per day",async()=>{
      await store.enqueue(companyA,"test");const next=await store.claim();await store.writeDevices(next.id,[{id:"device-A"}]);await store.finish(next);
      const result=await store.results(companyA,"cves",0);assert.equal(result.summary.findings,0);assert.equal(result.history.length,1);assert.equal(result.history[0].summary.findings,0);
    });
  } finally {
    await db.query("DELETE FROM defender_daily_history WHERE company_id=ANY($1)",[[companyA,companyB]]);
    await db.query("DELETE FROM defender_import_runs WHERE company_id=ANY($1)",[[companyA,companyB]]);
    await db.query("DELETE FROM defender_connections WHERE company_id=ANY($1)",[[companyA,companyB]]);
    await db.end();
  }
});

test("Defender connection endpoint cannot save or test browser-supplied credentials",async()=>{
 let syncs=0,tests=0;
 const code=ts.transpileModule(await readFile("app/api/defender/connections/route.ts","utf8"),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const mod=new SourceTextModule(code);
 const deps={
  "@/lib/defender-http":{defenderAccess:async()=>"member",defenderBody:request=>request.json(),defenderCompany:async id=>id,
   defenderJson:body=>Response.json(body),defenderFailure:error=>Response.json({error:error.message},{status:error.status ?? 500})},
  "@/lib/defender-client":{DefenderError:client.DefenderError,createDefenderClient:()=>({test:async()=>{tests++;return {ok:true};}})},
  "@/lib/defender-store":{defenderStore:()=>({credentials:async()=>credentials})},
  "@/lib/defender-config":{syncDefenderEnvironment:async()=>{syncs++;}},
 };
 await mod.link(name=>{const values=deps[name];return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});});await mod.evaluate();
 for(const body of [{action:"save",companyId:"customer",clientSecret:"fake"},{action:"test",companyId:"customer",clientSecret:"fake"}]){
  const response=await mod.namespace.POST(new Request("https://example.test/api/defender/connections",{method:"POST",body:JSON.stringify(body)}));assert.equal(response.status,403);
 }
 assert.equal(syncs,0);assert.equal(tests,0);
 const response=await mod.namespace.POST(new Request("https://example.test/api/defender/connections",{method:"POST",body:JSON.stringify({action:"test",companyId:"customer"})}));assert.equal(response.status,200);assert.equal(tests,1);
});
