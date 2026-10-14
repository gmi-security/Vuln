import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';

for(const route of ['connectors/sync-all','tidal/import'])test(`${route} progress remains readable while platform publication is blocked`,async()=>{
  const status={running:true,phase:'Saving completed import'},deps={
    '@/lib/platform-mutation-route':{withDurablePlatformMutation:handler=>handler},
    'next/server':{NextResponse:{json:Response.json}},
    '@/lib/store':{ensureHydrated:async()=>{throw Error('publication is busy');},startSyncAll(){},syncAllStatus:()=>status,startTidalSync(){},getTidalSyncStatus:()=>status},
  };
  const code=ts.transpileModule(await readFile(`app/api/${route}/route.ts`,'utf8'),{compilerOptions:{module:ts.ModuleKind.ESNext}}).outputText;
  const mod=new SourceTextModule(code);await mod.link(name=>new SyntheticModule(Object.keys(deps[name]),function(){for(const[k,v]of Object.entries(deps[name]))this.setExport(k,v);}));await mod.evaluate();
  assert.deepEqual(await(await mod.namespace.GET()).json(),{status});
});
