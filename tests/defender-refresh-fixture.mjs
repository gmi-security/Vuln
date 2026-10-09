import {readFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
// Actual existing projector/scorer/publication code, without application startup.
export async function refreshModules(){
  const modules=new Map();
  async function load(path){path=resolve(path);if(!modules.has(path))modules.set(path,new SourceTextModule(ts.transpileModule(await readFile(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path}));return modules.get(path);}
  async function link(name,parent){
    if(name.startsWith('.'))return load(resolve(dirname(parent.identifier),`${name}.ts`));
    if(name.startsWith('@/'))return load(resolve(`${name.slice(2)}.ts`));
    const imported=await import(name),values=name==='rrule'?{...imported.default,...imported}:imported;
    return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});
  }
  async function entry(path){const m=await load(path);if(m.status==='unlinked')await m.link(link);if(m.status!=='evaluated')await m.evaluate();return m.namespace;}
  return {store:await entry('lib/store.ts'),candidate:await entry('lib/defender-refresh-candidate.ts'),source:await entry('lib/defender-store.ts'),
    assessment:await entry('lib/defender-refresh-assessment.ts'),threat:await entry('lib/threat.ts')};
}
export const company={id:'CO-TEST',name:'Refresh fixture',kind:'client',createdAt:'2026-10-01T00:00:00Z'};
export const when='2026-10-09T12:00:00Z';
export const snapshot=(overrides={})=>({companyId:company.id,runId:'new-run',observedAt:when,
  devices:[{deviceId:'d1',hostname:'host1',ip:'',os:'Windows',lastSeen:when}],
  findings:[{deviceId:'d1',hostname:'host1',cve:'CVE-2026-1234',severity:'HIGH',cvss:8.1,firstSeen:when,lastSeen:when,remediation:'Install update',exploitAvailable:true}],...overrides});
export const storeFixture=()=>({companies:new Map([[company.id,company]]),folders:new Map(),scans:new Map(),findings:new Map(),assets:new Map(),
  compensatingControls:new Map(),identityAliases:new Map(),settings:{autoScanNewAssets:false,schedule:{autoSyncEnabled:false,scheduleEnabled:false,alertsEnabled:false,monthlyReportsEnabled:false},sla:{Critical:7,High:30,Medium:60,Low:90}},meta:{defenderGenerations:{}},seeded:true,counter:1000});
export function inputFrom(s,snap=snapshot()){
  return {company,baseline:{runId:s.meta.defenderGenerations[company.id]??null,savedAt:when,findings:[...s.findings.values()],assets:[...s.assets.values()]},source:{revision:1,snapshot:snap},assessmentContext:'fixture frozen KEV/control context'};
}
