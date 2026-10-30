// Uses only the verified disposable socket accepted by the integration suite.
import {readFile} from 'node:fs/promises';
import {SourceTextModule} from 'node:vm';
import ts from 'typescript';
import {startRuntimeMetrics} from '../lib/runtime-metrics.mjs';
process.env.VULN_GENERATION_TEST_ROWS='1340083';
process.env.VULN_GENERATION_TEST_CHANGED='856751';
const risk=new SourceTextModule(ts.transpileModule(await readFile('lib/risk-scoring.ts','utf8'),{
  compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
await risk.link(()=>{throw Error('Risk scoring must be a pure fixture');});await risk.evaluate();
const stopMetrics=startRuntimeMetrics({role:'isolated-publication-load'});
let scored=0,exportedBytes=0;
// Exercise the actual pure risk formula plus bounded scanner serialization,
// without vendor credentials, network calls, or a second application writer.
const busy=setInterval(()=>{
  const exportRows=[];
  for(let i=0;i<1000;i++){
    const score=risk.namespace.calculateRiskScore({cvssScore:9.8,epssProbability:0.9,cisaKev:true,
      assetCriticality:'High',assetType:'server',internetExposed:true,production:true});
    exportRows.push({id:scored++,score:score.total,scanner:'synthetic',details:'fixture evidence '.repeat(20)});
  }
  exportedBytes+=Buffer.byteLength(JSON.stringify(exportRows));
},250);busy.unref();
try { await import('./platform-generation-postgres.mjs'); }
finally {clearInterval(busy);stopMetrics();console.log(JSON.stringify({event:'load-work-complete',scored,exportedBytes}));}
