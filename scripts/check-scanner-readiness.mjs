// Explicit read-only probes using the existing scanner status functions.
// Never calls launch/import or prints vendor responses, URLs or credentials.
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import nextEnv from '@next/env';
import ts from 'typescript';
const specs=[['nessus','nessusServerStatus'],['spiderfoot','spiderfootStatus'],['artemis','artemisStatus'],['burp','burpStatus'],['nmap','nmapStatus'],['zap','zapStatus'],['vulners','vulnersStatus']];
const args=process.argv.slice(2),options={};
for(let i=0;i<args.length;i+=2){if(!['--env-file','--output'].includes(args[i])||!args[i+1]||options[args[i]])throw new Error('Use --env-file PATH --output NEW_PRIVATE_FILE');options[args[i]]=resolve(args[i+1]);}
if(!options['--env-file']||!options['--output'])throw new Error('Environment file and private output are required');
nextEnv.processEnv([{path:options['--env-file'],contents:await readFile(options['--env-file'],'utf8'),env:{}}],undefined,{info(){},error(){}},true);
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../lib');
const timeout=setTimeout(()=>{console.error('Readiness audit exceeded two minutes; no complete result.');process.exit(1);},120000);
const originalFetch=globalThis.fetch,originalError=console.error;
function failureClass(result) {
  if (!result.configured) return 'not-configured';
  if (result.reachable) return null;
  const message=String(result.message??'');
  if (/\b(401|403)\b/.test(message)) return 'authentication-or-permission';
  if (/\b404\b/.test(message)) return 'endpoint-not-found';
  if (/timed?\s*out|timeout/i.test(message)) return 'timeout';
  if (/ECONNREFUSED|refused/i.test(message)) return 'connection-refused';
  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(message)) return 'dns';
  if (/certificate|TLS|SSL/i.test(message)) return 'tls';
  if (/non-JSON|Unexpected token|JSON/i.test(message)) return 'unexpected-response';
  if (/HTTP 5\d\d/.test(message)) return 'upstream-server';
  return 'unclassified';
}
// All fetch-based probes get a deadline even if the legacy status lacks one.
globalThis.fetch=(input,init={})=>{
  const url=new URL(typeof input==='string'?input:input.url??input.href),method=(init.method??'GET').toUpperCase();
  const readPost=method==='POST' && (url.pathname==='/graphql/v1' && JSON.parse(init.body).query==='query { __typename }' || url.pathname==='/api/v3/search/lucene/');
  if(method!=='GET'&&!readPost)throw new Error('Non-readiness request blocked');
  return originalFetch(input,{...init,signal:init.signal?AbortSignal.any([init.signal,AbortSignal.timeout(12000)]):AbortSignal.timeout(12000)});
};
console.error=()=>{};
try {
  const results=[];
  for(const [provider,fn]of specs){
    const code=ts.transpileModule(await readFile(resolve(root,provider+'.ts'),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
    const mod=new SourceTextModule(code);
    await mod.link(async spec=>{
      if(spec==='@/lib/threat')return new SyntheticModule(['isKev'],function(){this.setExport('isKev',()=>{throw new Error('Finding processing is prohibited in readiness probes');});});
      if(spec==='./scanner-target-scope')return new SyntheticModule(['scannerTargetMatcher','assertScannerResultScope','scannerExactTargetKey','scannerWebOrigin'],function(){
        for(const name of ['scannerTargetMatcher','assertScannerResultScope','scannerExactTargetKey','scannerWebOrigin'])
          this.setExport(name,()=>{throw new Error('Target processing is prohibited in readiness probes');});
      });
      if(!['node:http','node:https','node:crypto'].includes(spec))throw new Error('Unexpected status dependency');
      const values=await import(spec);return new SyntheticModule(Object.keys(values),function(){for(const[k,v]of Object.entries(values))this.setExport(k,v);});
    });
    await mod.evaluate();const start=Date.now();
    try { const result=await mod.namespace[fn]();results.push({provider,configured:result.configured===true,reachable:result.reachable===true,
      ready:typeof result.ready==='boolean'?result.ready:null,failure:failureClass(result),elapsedMs:Date.now()-start}); }
    catch { results.push({provider,state:'probe-failed',elapsedMs:Date.now()-start}); }
  }
  const report={checkedAt:new Date().toISOString(),scope:'Existing scanner read-only status calls; not end-to-end import or tenant verification',configuration:'File plus audit process environment; not a PM2 environment attestation',results,scansLaunched:0,importsStarted:0};
  await writeFile(options['--output'],JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  process.stdout.write(JSON.stringify(report)+'\n');
}finally{globalThis.fetch=originalFetch;console.error=originalError;clearTimeout(timeout);}
