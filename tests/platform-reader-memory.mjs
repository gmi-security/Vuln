// Synthetic payloads only. Exercise the real reader/cache/view builder and
// request-context cleanup under an 8 GiB heap; never open a database connection.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule} from 'node:vm';
import {setImmediate as turn} from 'node:timers/promises';
import {EventEmitter} from 'node:events';
import ts from 'typescript';
import {loadCommittedPlatform} from '../lib/db/platform-reader.mjs';
import {platformBucketKeys} from '../lib/db/platform-store.mjs';
import {platformBucket,platformRecord,platformHash,platformJson} from '../lib/db/platform-records.mjs';
import {createCommittedCache} from '../lib/committed-cache.mjs';
import {createRuntimeRequestHandler} from '../scripts/runtime-server.mjs';
assert.equal(typeof global.gc,'function','Run with --expose-gc');
const size=Number(process.env.READER_MEMORY_ROWS??1340083),cycles=Number(process.env.READER_MEMORY_CYCLES??3);
const source=await readFile('lib/store.ts','utf8'),ast=ts.createSourceFile('store.ts',source,ts.ScriptTarget.Latest,true);
const names=new Set(['immutableMap','freezeReadMetadata','prepareCommittedView']);
const functions=ast.statements.filter(node=>ts.isFunctionDeclaration(node)&&names.has(node.name?.text)).map(node=>node.getText(ast)).join('\n');
assert.equal(ast.statements.filter(node=>ts.isFunctionDeclaration(node)&&names.has(node.name?.text)).length,3);
// Only metadata normalization is substituted; the production collection/view
// builder is extracted verbatim so this fixture cannot drift into a copy.
const build=new SourceTextModule(ts.transpileModule(`
function deserializeStore(meta){return {...meta,identityAliases:new Map(),compensatingControls:new Map(),settings:{},meta:{},retainedMetadata:{}};}
${functions}\nexport {prepareCommittedView};`,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText);
await build.link(()=>{throw Error('unexpected view dependency');});await build.evaluate();
const indices=Array.from({length:64},()=>[]);
for(let i=0;i<size;i++){indices[platformBucket('F-'+i,64)].push(i);if(i%2000===0)await turn();}
let revision=1,peakHeap=0;
const measure=()=>{peakHeap=Math.max(peakHeap,process.memoryUsage().heapUsed);};
const sample=setInterval(measure,100);sample.unref();
const metadata={counter:1},metaHash=platformHash(platformJson(metadata));
const client={async query(sql,params=[]){
  measure();
  if(sql.includes('to_regclass'))return {rows:[{relation:'app_store_authority'}]};
  if(sql.includes('FROM public.app_store_authority'))return {rows:[{mode:'sql',enforced:true,epoch:'2',revision:String(revision)}]};
  if(sql.includes('FROM app_store_commits'))return {rows:[{epoch:'2',revision:String(revision),operation:'save',counts:{inserted:0,updated:size,deleted:0,metadata:0,changedKeys:platformBucketKeys.filter(k=>k.startsWith('findings:'))}}]};
  if(sql.includes('FROM app_store_metadata'))return {rows:[{payload:metadata,record_hash:metaHash}]};
  if(sql.includes('FROM app_findings')){
    const list=indices[params[0]],after=params[1];let low=0,high=list.length;
    while(low<high){const mid=(low+high)>>1;if(list[mid]<=after)low=mid+1;else high=mid;}
    return {rows:list.slice(low,low+500).map(i=>{
      const id='F-'+i,payload={id,companyId:'CO-1',status:revision%2?'Open':'In Remediation',cve:`CVE-2026-${10000+i%10000}`,
        remediation:`Synthetic update instructions for host ${i}. `+'Install the vendor update and verify the version. '.repeat(26),
        evidence:{source:'synthetic',observedAt:'2026-10-30T00:00:00Z',revision}};
      return platformRecord('findings',[id,payload],i);
    })};
  }
  if(sql.startsWith('SELECT id,payload'))return {rows:[]};
  throw Error('Unexpected fixture query');
}};
const cache=createCommittedCache({load:previous=>loadCommittedPlatform(client,previous),build:build.namespace.prepareCommittedView});
let held;
const handler=createRuntimeRequestHandler({role:'web',socketPath:'unused',token:'fixture',handleRequest(){
  held=globalThis[Symbol.for('vuln.readContext')].getStore();held.platform=cache.current();
}});
const quiescent=[];
try{
 for(let cycle=1;cycle<=cycles;cycle++){
  const started=performance.now();await cache.refresh();measure();
  const req=Object.assign(new EventEmitter(),{method:'GET',url:'/api/companies',headers:{},rawHeaders:[]}),res=new EventEmitter();
  handler(req,res);await turn();
  const old=new WeakRef(cache.current().view.findings);revision++;
  await cache.refresh();measure();
  assert.equal(held.platform.snapshot.authority.revision,String(revision-1),'slow request retains its original view');
  if(cycle%2)res.emit('finish');else req.emit('aborted');
  assert.equal(held.platform,undefined);held=null;
  for(let i=0;i<4;i++){await turn();global.gc();}
  assert.equal(old.deref(),undefined,'retired view must be collectible after request completion/abort');
  const heap=process.memoryUsage().heapUsed;quiescent.push(heap);
  console.log(JSON.stringify({cycle,rows:size,elapsedMs:Math.round(performance.now()-started),heapBytes:heap,peakHeapBytes:peakHeap}));
 }
 assert.ok(Math.max(...quiescent)-Math.min(...quiescent)<Math.max(100*1024*1024,quiescent[0]*0.1),'quiescent heap accumulates across generations');
 assert.ok(peakHeap<6*1024**3,'peak exceeds the proposed 6 GiB ceiling; investigate capacity before claiming memory recovery');
}finally{clearInterval(sample);cache.stop();}
