import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
async function load(name){const mod=new SourceTextModule(ts.transpileModule(await readFile(`lib/${name}.ts`,'utf8'),
 {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
 await mod.link(()=>{throw Error('Unexpected adapter dependency');});await mod.evaluate();return mod.namespace;}
const tidal=await load('tidal'),falcon=await load('crowdstrike'),cid='a'.repeat(32),config={clientId:'fixture',clientSecret:'fixture',baseUrl:'https://fixture.invalid'};
async function transport(handler,run){const before=globalThis.fetch;globalThis.fetch=handler;try{return await run();}finally{globalThis.fetch=before;}}
const json=Response.json;
test('CrowdStrike returns CID-verified complete inventory; every host must match the reviewed CID and requested IDs',async()=>{
 let mode='ok',posts=0;
 await transport(async(raw,options)=>{
  const path=new URL(raw).pathname;
  if(path==='/oauth2/token')return json({access_token:'fixture'});
  if(path.includes('/queries/'))return json({resources:['d1','d2'],meta:{pagination:{total:2}}});
  assert.equal(path,'/devices/entities/devices/v2');assert.deepEqual(JSON.parse(options.body).ids,['d1','d2']);posts++;
  const rows=[{device_id:'d1',cid,hostname:'host-a'},{device_id:'d2',cid}];
  if(mode==='foreign')rows[1].cid='b'.repeat(32);
  if(mode==='missing-cid')delete rows[1].cid;
  if(mode==='missing-id')delete rows[1].device_id;
  if(mode==='wrong-id')rows[1].device_id='unrequested';
  if(mode==='duplicate')rows[1].device_id='d1';
  return json(mode==='malformed'?{resources:{}}:{resources:mode==='partial'?rows.slice(0,1):rows,...(mode==='errors'?{errors:[{code:404}]}:{})});
 },async()=>{
  const result=await falcon.falconListAssets(config,undefined,{expectedCid:cid.toUpperCase()});assert.equal(result.length,2);assert.equal(result[1].externalId,'d2');
  for(mode of ['foreign','missing-cid','missing-id','wrong-id','duplicate','malformed','partial','errors'])
   await assert.rejects(()=>falcon.falconListAssets(config,undefined,{expectedCid:cid}),/does not completely match/);
  // Existing callers without reviewed routing retain their response contract.
  mode='foreign';assert.equal((await falcon.falconListAssets(config)).length,2);assert.equal(posts,10);
 });
});
test('CrowdStrike stops malformed, incomplete, capped or empty reviewed discovery before hydration',async()=>{
 let response,entities=0,auth=0;
 await transport(async(raw)=>{
  const path=new URL(raw).pathname;
  if(path==='/oauth2/token'){auth++;return json({access_token:'fixture'});}
  if(path.includes('/queries/'))return json(response);
  entities++;throw Error('Hydration must not start');
 },async()=>{
  await assert.rejects(()=>falcon.falconListAssets(config,undefined,{expectedCid:'bad'}),/valid reviewed CID/);assert.equal(auth,0);
  for(response of [{},{resources:'bad'}, {resources:['d1'],meta:{pagination:{total:2}}},
   {resources:['d1','d1'],meta:{pagination:{total:2}}},{resources:['d1'],meta:{pagination:{total:1}},errors:[{code:400}]},
   {resources:[],meta:{pagination:{total:0}}},{resources:Array.from({length:500},(_,i)=>'d'+i),meta:{pagination:{total:10001}}}])
    await assert.rejects(()=>falcon.falconListAssets(config,undefined,{expectedCid:cid}),/incomplete|invalid|no hosts|10,000/);
  assert.equal(entities,0);
 });
});
test('CrowdStrike rejects duplicate devices or a changed total across pages before collecting details',async()=>{
 let mode='ok',entities=0;const ids=Array.from({length:501},(_,i)=>'d'+i);
 await transport(async(raw,options)=>{
  const url=new URL(raw);
  if(url.pathname==='/oauth2/token')return json({access_token:'fixture'});
  if(url.pathname.includes('/queries/')){
   const offset=Number(url.searchParams.get('offset'));
   return json({resources:offset?[mode==='duplicate'?'d0':'d500']:ids.slice(0,500),meta:{pagination:{total:offset&&mode==='changed'?502:501}}});
  }
  entities++;return json({resources:JSON.parse(options.body).ids.map(device_id=>({device_id,cid}))});
 },async()=>{
  assert.equal((await falcon.falconListAssets(config,undefined,{expectedCid:cid})).length,501);assert.equal(entities,2);
  for(mode of ['duplicate','changed'])await assert.rejects(()=>falcon.falconListAssets(config,undefined,{expectedCid:cid}),/repeated|incomplete/);
  assert.equal(entities,2);
 });
});
test('Tidal collects only selected company sessions and stamps server IDs independently of name or row content',async()=>{
 const tidalConfig={url:'https://fixture.invalid',origin:'https://fixture.invalid',email:'fixture',password:'fixture'};
 let mode='ok',switched=[],requests=0,company;
 await transport(async(raw,options)=>{
  requests++;const path=new URL(raw).pathname;
  if(path==='/auth/csrf-cookie')return new Response('',{headers:{'set-cookie':'XSRF-TOKEN=fixture; Path=/'}});
  if(path==='/auth/login')return json({ok:true});
  if(path==='/api/v1/admin/companies')return json({data:[{id:'Vendor-A',name:'Same name'},{id:mode==='duplicate'?'Vendor-A':'Vendor-B',name:'Same name'}]});
  if(path.endsWith('/switch-company')){company=JSON.parse(options.body).company_id;switched.push(company);return new Response('',{status:mode==='switch-fail'?403:200});}
  if(path.endsWith('/auvik/tenants'))return json([]);
  if(path.endsWith('/intune/devices'))return json({data:[{device_id:'d1',device_name:'host-a',customer:'Wrong name',sourceCompanyId:'Vendor-B'}]});
  if(path.endsWith('/devices'))return new Response('',{status:404});
  throw Error('Unexpected fixture request');
 },async()=>{
  await assert.rejects(()=>tidal.tidalListAssets(undefined,{config:tidalConfig,companyIds:new Set()}));assert.equal(requests,0);
  const result=await tidal.tidalListAssets(undefined,{config:tidalConfig,companyIds:new Set(['Vendor-A','Missing'])});
  assert.deepEqual(switched,['Vendor-A']);assert.equal(result.skippedCompanies,1);assert.equal(result.errors.length,1);
  assert.equal(result.assets[0].sourceCompanyId,'Vendor-A');assert.equal(result.assets[0].customer,'Same name');
  const parsed=tidal.parseTidalCsv('Hostname,Customer,sourceCompanyId\nhost-a,Same name,Vendor-A');assert.equal(parsed[0].sourceCompanyId,undefined);
  switched=[];mode='duplicate';await assert.rejects(()=>tidal.tidalListAssets(undefined,{config:tidalConfig,companyIds:new Set(['Vendor-A'])}),/duplicate company identities/);assert.deepEqual(switched,[]);
  mode='ok';await assert.rejects(()=>tidal.tidalListAssets(undefined,{config:tidalConfig,companyIds:new Set(['vendor-a'])}),/no approved companies/);assert.deepEqual(switched,[]);
  mode='switch-fail';const error=console.error;console.error=()=>{};
  try{await assert.rejects(()=>tidal.tidalListAssets(undefined,{config:tidalConfig,companyIds:new Set(['Vendor-A'])}),/switch-company failed/);}finally{console.error=error;}
 });
});
test('Falcon configuration keeps a stable source reference independent of display label',()=>{
 const keys=Object.keys(process.env).filter(k=>k.startsWith('FALCON_')),before=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
 try{
  for(const key of keys)delete process.env[key];
  Object.assign(process.env,{FALCON_CLIENT_ID:'fixture',FALCON_CLIENT_SECRET:'fixture',FALCON_CLIENT_ID_2:'fixture2',FALCON_CLIENT_SECRET_2:'fixture',FALCON_CUSTOMER_2:'Name'});
  assert.deepEqual(falcon.falconConfigs().map(c=>c.sourceRef),['environment:FALCON','environment:FALCON_2']);
  process.env.FALCON_CUSTOMER_2='Renamed';assert.equal(falcon.falconConfigs()[1].sourceRef,'environment:FALCON_2');
 }finally{for(const key of Object.keys(process.env).filter(k=>k.startsWith('FALCON_')))delete process.env[key];Object.assign(process.env,before);}
});
test('Tidal CSV HTTP endpoint exposes reviewed-routing refusal and preserves successful legacy responses',async()=>{
 let rejected=true;
 const code=ts.transpileModule(await readFile('app/api/tidal/import-file/route.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const values={
  'next/server':{NextResponse:{json:(data,init)=>Response.json(data,init)}},
  '@/lib/store':{ensureHydrated:async()=>{},importTidalInventory:async()=>rejected?{error:'Use live Tidal sync for reviewed routing.'}:{assetsUpserted:1}},
  '@/lib/tidal':{parseTidalCsv:tidal.parseTidalCsv},
 };
 const mod=new SourceTextModule(code);await mod.link(name=>{assert.ok(values[name]);return new SyntheticModule(Object.keys(values[name]),function(){for(const[k,v]of Object.entries(values[name]))this.setExport(k,v);});});await mod.evaluate();
 const request=()=>new Request('http://fixture.invalid/api/tidal/import-file',{method:'POST',body:'Hostname,Customer\nhost-a,Alpha'});
 let result=await mod.namespace.POST(request());assert.equal(result.status,409);assert.match((await result.json()).error,/live Tidal/);
 rejected=false;result=await mod.namespace.POST(request());assert.equal(result.status,200);assert.equal((await result.json()).result.rowsParsed,1);
});
