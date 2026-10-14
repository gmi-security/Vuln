import {readFile} from 'node:fs/promises';
import {resolve,dirname,extname} from 'node:path';
import {SourceTextModule,SyntheticModule,createContext} from 'node:vm';
import ts from 'typescript';

// Real store/reference code in a fixed-time, credential-free VM. A report must
// not start timers, call providers or initialize persistence in these checks.
export async function executiveHarness(now=Date.parse('2026-10-10T12:00:00Z')){
 class FixedDate extends Date {constructor(...args){super(...(args.length?args:[now]));}static now(){return now;}}
 const forbidden=()=>{throw Error('Executive report attempted external work');};
 const context=createContext({process:{env:{VULN_DISABLE_SCHEDULER:'true'}},Date:FixedDate,Buffer,URL,URLSearchParams,
  console,fetch:forbidden,setInterval:forbidden,setTimeout:forbidden,clearInterval:forbidden,clearTimeout:forbidden,
  setImmediate:forbidden,structuredClone,AbortController,TextEncoder,TextDecoder});
 const cache=new Map();
 const file=p=>extname(p)?resolve(p):resolve(p+'.ts');
 async function load(path){
  path=file(path);if(cache.has(path))return cache.get(path);
  const promise=(async()=>{
   const raw=await readFile(path,'utf8'),code=path.endsWith('.ts')?ts.transpileModule(raw,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText:raw;
   return new SourceTextModule(code,{identifier:path,context});
  })();cache.set(path,promise);return promise;
 }
 async function link(spec,parent){
  if(spec.startsWith('@/'))return load(spec.slice(2));
  if(spec.startsWith('.'))return load(resolve(dirname(parent.identifier),spec));
  const imported=await import(spec),values=spec==='rrule'?{...imported.default,...imported}:imported;
  return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);},{context});
 }
 async function entry(path){const mod=await load(path);if(mod.status==='unlinked')await mod.link(link);if(mod.status!=='evaluated')await mod.evaluate();return mod.namespace;}
 const store=await entry('lib/store.ts'),executive=await entry('lib/executive-report.ts'),legacy=await entry('tests/fixtures/legacy-executive-report.ts');
 const threat=await entry('lib/threat.ts');
 return {store,executive,legacy,threat,now,setState:s=>context.__vulnStore=s};
}
