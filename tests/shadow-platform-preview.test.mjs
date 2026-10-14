import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
import {shadowPlatformRequest} from '../lib/db/shadow-platform-comparison.mjs';
import {shadowCursor} from '../lib/db/defender-shadow-reads.mjs';
class DashboardError extends Error{constructor(message,status){super(message);this.status=status;}}
const projectionId='11111111-1111-1111-1111-111111111111';
const raw={companyId:'CO-A',view:'findings',status:'open',limit:'100'};
test('platform request bounds and cursor scope are checked before storage',()=>{
  const cursor=shadowCursor({...raw,projectionId},100);
  assert.equal(shadowPlatformRequest({...raw,cursor}).limit,100);
  assert.deepEqual(shadowPlatformRequest({companyId:'CO-A'}),{companyId:'CO-A',view:'summary',status:'open',limit:50,cursor:null});
  for(const change of [{companyId:''},{view:'all'},{status:'closed'},{limit:'101'},{limit:'0'},{limit:'01'},{limit:'1.5'},{limit:'1e2'},{limit:' 1'},
    {projectionId},{source:'defender'},{cursor:'bad'},{cursor:cursor+'='},{cursor:'x'.repeat(1025)},
    {companyId:'CO-B',cursor},{view:'cves',cursor},{view:'summary',cursor},{status:'all',cursor}])assert.throws(()=>shadowPlatformRequest({...raw,...change}),e=>e.status===400);
});
async function load(file,stubs){
  const code=ts.transpileModule(await readFile(file,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const mod=new SourceTextModule(code);await mod.link(name=>{
    assert.ok(stubs[name],`Unexpected import ${name}`);return new SyntheticModule(Object.keys(stubs[name]),function(){for(const [k,v]of Object.entries(stubs[name]))this.setExport(k,v);});
  });await mod.evaluate();return mod.namespace;
}
async function env(values,fn){const old={};for(const[k,v]of Object.entries(values)){old[k]=process.env[k];process.env[k]=v;}
  try{return await fn();}finally{for(const[k,v]of Object.entries(old)){if(v===undefined)delete process.env[k];else process.env[k]=v;}}}
test('platform HTTP route authenticates first, enforces flags and rejects overrides/duplicates',async()=>{
  for(const mode of ['unauth','disabled','ui-disabled','valid','duplicate','override']){
    const calls=[];const api=await load('app/api/elastic-dashboard/customer-platform-comparison/route.ts',{
      '@/lib/elastic-dashboard-http':{dashboardAccess:async()=>{calls.push('auth');if(mode==='unauth')throw new DashboardError('Unauthorized',401);},dashboardFailure:e=>({status:e.status??503}),dashboardJson:value=>({status:200,value})},
      '@/lib/elastic-dashboard':{DashboardError},'@/lib/remediation-server':{remediationUiEnabled:()=>mode!=='ui-disabled'},
      '@/lib/shadow-platform-preview':{readShadowPlatformPreview:async r=>{calls.push('read');return r;}},
    });
    const query='companyId=CO-A'+(mode==='duplicate'?'&limit=1&limit=2':mode==='override'?'&projectionId='+projectionId:'');
    const response=await env({VULN_SHADOW_CVE_READS:mode==='disabled'?'false':'true'},()=>api.GET(new Request('http://fixture/?'+query)));
    assert.equal(response.status,mode==='unauth'?401:['disabled','ui-disabled'].includes(mode)?404:['duplicate','override'].includes(mode)?400:200);
    assert.deepEqual(calls,mode==='valid'?['auth','read']:['auth']);assert.equal(api.POST,undefined);
  }
});
test('platform service uses only metadata and shadow clients, releases them on all outcomes',async()=>{
  for(const mode of ['available','unpublished','disabled','pinned','invalid','unknown','metadata-failure','connect-failure','read-failure']){
    const calls=[];const api=await load('lib/shadow-platform-preview.ts',{
      './persist':{applicationDatabase:()=>({connect:async()=>{calls.push('metadata-connect');return{release(){calls.push('metadata-release');}};}})},
      './elastic-dashboard':{DashboardError},
      './shadow-cve-preview':{
        shadowCveBindings:()=>mode==='unknown'?[]:[{companyId:'CO-A',source:'defender',...(mode==='pinned'?{projectionId}:{selection:'published'})}],
        resolveShadowComparisonCustomer:async()=>{if(mode==='metadata-failure')throw new DashboardError('Customer not found',404);return{company:{name:'Fixture'}};},
        readShadowComparisonPool:(kind)=>{assert.equal(kind,'shadow');return{connect:async()=>{calls.push('shadow-connect');if(mode==='connect-failure')throw Error('Unavailable');return{release(){calls.push('shadow-release');}};}};},
      },
      './db/shadow-platform-comparison.mjs':{shadowPlatformRequest,readShadowPlatformComparison:async()=>{calls.push('read');if(mode==='read-failure')throw Object.assign(Error('Publication changed'),{status:409});return{state:mode,companyId:'CO-A'};}},
    });
    await env({VULN_SHADOW_CVE_READS:mode==='disabled'?'false':'true',VULN_SHADOW_DATABASE_URL:'fixture'},async()=>{
      if(['available','unpublished'].includes(mode))assert.deepEqual(await api.readShadowPlatformPreview(raw),{state:mode,companyId:'CO-A',companyName:'Fixture'});
      else await assert.rejects(()=>api.readShadowPlatformPreview(mode==='invalid'?{...raw,limit:'101'}:raw));
    });
    if(['disabled','pinned','invalid','unknown'].includes(mode))assert.deepEqual(calls,[]);
    else{
      assert.equal(calls.filter(x=>x==='metadata-release').length,1);
      if(mode==='metadata-failure')assert.ok(!calls.includes('shadow-connect'));
      else if(mode!=='connect-failure'){assert.equal(calls.at(-1),'shadow-release');assert.ok(calls.indexOf('metadata-release')<calls.indexOf('shadow-connect'));}
    }
  }
});
