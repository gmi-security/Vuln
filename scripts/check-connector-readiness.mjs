// Explicit bounded read-only/authentication checks. No store/worker imports,
// schema initializers, ingestion, scans, tickets or mail. Output is aggregate.
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import nextEnv from '@next/env';
import ts from 'typescript';
import pg from 'pg';
import {applicationDatabaseSsl} from '../lib/db/connection-target.mjs';
const options={};for(let i=2;i<process.argv.length;i+=2){const k=process.argv[i],v=process.argv[i+1];if(!['--env-file','--output'].includes(k)||!v||options[k])throw Error('Use --env-file PATH --output NEW_PRIVATE_FILE');options[k]=resolve(v);}
if(!options['--env-file']||!options['--output'])throw Error('Explicit environment file and private output required');
nextEnv.processEnv([{path:options['--env-file'],contents:await readFile(options['--env-file'],'utf8'),env:{}}],undefined,{info(){},error(){}},true);
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../lib'),cache=new Map();
const allowed=new Set(['defender-client','crowdstrike','threat-intel-refresh','elastic-query-client','elastic-dashboard','connectwise-client','connectwise-automate','tidal']);
async function load(name){
 if(!allowed.has(name))throw Error('Unexpected probe dependency');if(cache.has(name))return cache.get(name);
 let source=await readFile(resolve(root,name+'.ts'),'utf8');
 // Expose only the existing roster/login functions for the operator probe.
 // Application code and the vendor API are unchanged; no tenant switching.
 if(name==='tidal')source+='\nexport { tidalLogin, listCompanies };';
 const m=new SourceTextModule(ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);cache.set(name,m);
 await m.link(async spec=>{if(spec.startsWith('./'))return load(spec.slice(2));
  if(!['node:crypto','node:https','node:dns/promises'].includes(spec))throw Error('Unexpected probe import');
  const exports=await import(spec);return new SyntheticModule(Object.keys(exports),function(){for(const[k,v]of Object.entries(exports))this.setExport(k,v);});});
 return m;
}
async function api(name){const m=await load(name);if(m.status!=='evaluated')await m.evaluate();return m.namespace;}
const realFetch=globalThis.fetch,realError=console.error;let calls=0,current=[],failedLogs=0;
globalThis.fetch=async(input,init={})=>{
 const u=new URL(typeof input==='string'?input:input.href??input.url),method=(init.method??'GET').toUpperCase();
 const post=method==='POST'&&(/\/oauth2\/(v2\.0\/)?token$/.test(u.pathname)||u.pathname.endsWith('/apitoken')||u.pathname==='/auth/login'||u.pathname.endsWith('/attributes/restSearch')||
  u.pathname.endsWith('/graphql')&&JSON.parse(init.body).query.trim().startsWith('query'));
 if(method!=='GET'&&!post||++calls>100)throw Error('Probe request policy exceeded');
 const response=await realFetch(input,{...init,redirect:'error',signal:init.signal?AbortSignal.any([init.signal,AbortSignal.timeout(12000)]):AbortSignal.timeout(12000)});
 current.push(response.status);return response;
};
console.error=(...values)=>{const s=values.join(' ');const n=/\b(\d+) failed/.exec(s);if(n)failedLogs+=Number(n[1]);};
const results=[],clients=[],timer=setTimeout(()=>{realError('Connector audit exceeded five minutes; result incomplete.');process.exit(1);},300000);
async function probe(provider,scope,work){const started=Date.now();current=[];failedLogs=0;
 try{const detail=await work();if(failedLogs||current.some(n=>n>=400))throw Error('Source reported probe failure');results.push({provider,scope,state:'reachable',elapsedMs:Date.now()-started,...detail});}
 catch(error){const status=current.find(n=>n>=400)??(Number.isInteger(error?.status)?error.status:null);
  results.push({provider,scope,state:'unavailable',httpStatus:status,failedRequests:failedLogs,elapsedMs:Date.now()-started});}
}
async function database(url){if(!url)throw Error('Database configuration missing');const c=new pg.Client({connectionString:url,ssl:applicationDatabaseSsl(url),connectionTimeoutMillis:10000});await c.connect();clients.push(c);await c.query("BEGIN READ ONLY;SET LOCAL statement_timeout='10s';SET LOCAL idle_in_transaction_session_timeout='330s'");return c;}
async function saved(db,table,where=''){if(!(await db.query('SELECT to_regclass($1) relation',['public.'+table])).rows[0].relation)return[];return(await db.query(`SELECT secret FROM ${table} ${where} LIMIT 100`)).rows;}
try{
 const cs=await api('crowdstrike');let n=0;
 for(const config of cs.falconConfigs())await probe('crowdstrike',`environment-${++n}`,async()=>{const r=await cs.falconProbeCounts(config);if(r.hostsError||r.spotlightError)throw Error('CrowdStrike read failed');return{hosts:r.hostsAvailable,findings:r.spotlightFindingsAvailable};});
 const app=await database(process.env.DATABASE_URL),dashboard=process.env.ELASTIC_VULN_DATABASE_URL&&process.env.ELASTIC_VULN_DATABASE_URL!==process.env.DATABASE_URL?await database(process.env.ELASTIC_VULN_DATABASE_URL):app;
 const defender=await api('defender-client');n=0;
 for(const row of await saved(app,'defender_connections'))await probe('defender',`saved-${++n}`,async()=>{await defender.createDefenderClient(defender.openDefender(row.secret)).test();return{deviceAndVulnerabilityRead:true};});
 if(process.env.DEFENDER_TENANT_ID&&process.env.DEFENDER_CLIENT_ID&&process.env.DEFENDER_CLIENT_SECRET)await probe('defender','environment',async()=>{
  await defender.createDefenderClient({tenantId:process.env.DEFENDER_TENANT_ID,clientId:process.env.DEFENDER_CLIENT_ID,clientSecret:process.env.DEFENDER_CLIENT_SECRET}).test();return{deviceAndVulnerabilityRead:true};});
 const es=await api('elastic-query-client');
 for(const row of await saved(dashboard,'elastic_dashboard_connection','WHERE id=1'))await probe('elastic','saved-query-connection',async()=>{await es.executeEsql(es.openConnection(row.secret),'ROW ready = 1');return{queryTransport:true,datasetOwnershipVerified:false};});
 if(process.env.APPSEC_ELASTIC_URL&&process.env.APPSEC_ELASTIC_API_KEY)await probe('appsec','environment',async()=>{
  const connection={endpoint:process.env.APPSEC_ELASTIC_URL,apiKey:process.env.APPSEC_ELASTIC_API_KEY};
  for(const stream of [process.env.APPSEC_ELASTIC_SCAN_STREAM||'gmi-appsec-scans',process.env.APPSEC_ELASTIC_FINDING_STREAM||'gmi-appsec-findings']){
   if(!/^[a-zA-Z0-9_.-]+$/.test(stream))throw Error('Explicit AppSec stream required');await es.executeEsql(connection,`FROM ${stream}\n| LIMIT 1\n| STATS rows = COUNT(*)`);
  }return{streamsReadable:true,repositoryOwnershipVerified:false};});
 const cw=await api('connectwise-client');
 for(const row of await saved(dashboard,'patch_connectwise_connection','WHERE id=1'))await probe('connectwise','saved-ticket-connection',async()=>{const r=await cw.cwOptions(cw.openCWConnection(row.secret),'boards');return{boardsOnFirstPage:r.options.length,ticketCreationTested:false};});
 const intel=await api('threat-intel-refresh');
 for(const [provider,url,key,fn]of [['misp','MISP_URL','MISP_API_KEY','fetchMispActiveExploitation'],['opencti','OPENCTI_URL','OPENCTI_API_KEY','fetchOpenCtiActiveExploitation']])
  if(process.env[url]&&process.env[key])await probe(provider,'environment',async()=>{const r=await intel[fn](['CVE-2021-44228']);return{queryAccepted:true,cvesWithData:r.size};});
 const automate=await api('connectwise-automate'),a=automate.automateConfig();if(a)await probe('automate','environment',async()=>({customers:(await automate.automateListClients(a)).length}));
 const tidal=await api('tidal'),t=tidal.tidalConfig();if(t)await probe('tidal','environment',async()=>({customers:(await tidal.listCompanies(t,await tidal.tidalLogin(t),true)).length}));
 const report={checkedAt:new Date().toISOString(),scope:'Read/authentication probes only; source ownership and write permissions are separate acceptance checks',configuration:'Environment file and saved encrypted connections, not running PM2 environment attestation',results,importsStarted:0,scansLaunched:0,ticketsCreated:0};
 await writeFile(options['--output'],JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});process.stdout.write(JSON.stringify(report)+'\n');
}finally{clearTimeout(timer);for(const c of clients){await c.query('ROLLBACK').catch(()=>{});await c.end();}globalThis.fetch=realFetch;console.error=realError;}
