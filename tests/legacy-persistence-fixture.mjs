import {readFile} from 'node:fs/promises';
import {createContext,SourceTextModule,SyntheticModule} from 'node:vm';
import * as crypto from 'node:crypto';
import ts from 'typescript';
// The actual bucket writer/reader with only its Pool and process environment
// injected. The caller supplies a disposable source pool, never credentials.
export async function legacyPersistenceFixture(pool){
  let onWrite;
  const wrapper={on(){},end:()=>pool.end(),query:(...args)=>pool.query(...args),connect:async()=>{
    const client=await pool.connect();return {release:error=>client.release(error),query:async(sql,params)=>{
      if(sql.startsWith('INSERT INTO vuln_store'))await onWrite?.(sql,params);
      return client.query(sql,params);
    }};
  }};
  async function fresh(){
    const context=createContext({process:{env:{DATABASE_URL:'postgresql://localhost/disposable-test-only'}},console,Buffer,setTimeout,clearTimeout,setImmediate});
    const code=ts.transpileModule(await readFile('lib/persist.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
    const mod=new SourceTextModule(code,{context});
    await mod.link(async name=>{if(!['pg','node:crypto'].includes(name))throw Error('Unexpected persistence dependency');
      const values=name==='pg'?{Pool:class{constructor(){return wrapper;}}}:crypto;
      return new SyntheticModule(Object.keys(values),function(){for(const key of Object.keys(values))this.setExport(key,values[key]);},{context});
    });await mod.evaluate();return mod.namespace;
  }
  return {persist:await fresh(),fresh,onWrite:fn=>{onWrite=fn;}};
}
