// Read-only review evidence. Historical records are proposals, never approvals.
import {readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import pg from 'pg';
import nextEnv from '@next/env';
import {applicationDatabaseSsl} from '../lib/db/connection-target.mjs';
import {readPlatformAuthority} from '../lib/db/platform-authority.mjs';
import {readApplicationConnectorMetadata,readDashboardConnectorMetadata} from '../lib/db/connector-metadata.mjs';
const args=process.argv.slice(2);
if(args.length!==4||args[0]!=='--env-file'||args[2]!=='--output')throw Error('Use --env-file PATH --output NEW_PRIVATE_FILE');
nextEnv.processEnv([{path:resolve(args[1]),contents:await readFile(args[1],'utf8'),env:{}}],undefined,{info(){},error(){}},true);
const clients=[];
async function connect(url){const c=new pg.Client({connectionString:url,ssl:applicationDatabaseSsl(url),connectionTimeoutMillis:5000,
 statement_timeout:15000,options:'-c default_transaction_read_only=on',application_name:'vuln-customer-assignment-review'});clients.push(c);await c.connect();return c;}
const safeTarget=value=>{if(typeof value!=='string')return '[review in scanner]';
 if(/^https?:\/\//i.test(value)){try{const u=new URL(value);return u.origin;}catch{return '[review in scanner]';}}
 return /^[a-zA-Z0-9.*:/_-]{1,253}$/.test(value)?value:'[review in scanner]';};
const safeRef=value=>typeof value==='string'&&/^[a-zA-Z0-9_.:-]{1,160}$/.test(value)?value:null;
try{
 const app=await connect(process.env.DATABASE_URL),dashboard=process.env.ELASTIC_VULN_DATABASE_URL&&process.env.ELASTIC_VULN_DATABASE_URL!==process.env.DATABASE_URL?await connect(process.env.ELASTIC_VULN_DATABASE_URL):app;
 const application=await readApplicationConnectorMetadata(app),saved=await readDashboardConnectorMetadata(dashboard);
 await app.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 const sql=(await readPlatformAuthority(app))?.mode==='sql';
 const rows=(await app.query(sql?
  `SELECT payload->>'id' id,company_id,payload->>'connector' connector,payload->>'externalRef' reference,
   payload->'targets' targets,payload->>'status' status,payload->>'completedAt' completed_at FROM app_scans ORDER BY id LIMIT 10001`:
  `SELECT r->1->>'id' id,r->1->>'companyId' company_id,r->1->>'connector' connector,r->1->>'externalRef' reference,
   r->1->'targets' targets,r->1->>'status' status,r->1->>'completedAt' completed_at
   FROM vuln_store s,LATERAL jsonb_array_elements(CASE WHEN s.key ~ '^scans:[0-9]+$' THEN s.data ELSE '[]'::jsonb END) r
   WHERE s.key ~ '^scans:[0-9]+$' ORDER BY 1 LIMIT 10001`)).rows;
 if(rows.length>10000)throw Error('Too many scans for a bounded assignment review');
 const inventory=(await app.query(sql?
  `SELECT company_id,source,count(*)::int count FROM app_assets GROUP BY 1,2 LIMIT 1001`:
  `SELECT r->1->>'companyId' company_id,r->1->>'source' source,count(*)::int count FROM vuln_store s,
   LATERAL jsonb_array_elements(CASE WHEN s.key ~ '^assets:[0-9]+$' THEN s.data ELSE '[]'::jsonb END) r
   WHERE s.key ~ '^assets:[0-9]+$' GROUP BY 1,2 LIMIT 1001`)).rows;
 if(inventory.length>1000)throw Error('Too many inventory groups');await app.query('COMMIT');
 const companies=application.companies.map(company=>{
  const own=rows.filter(r=>r.company_id===company.id),groups=new Map();
  for(const row of own){if(!/^[a-z]+$/.test(row.connector??''))continue;
   let group=groups.get(row.connector);if(!group)groups.set(row.connector,group={provider:row.connector,scans:0,completed:0,references:new Set(),targets:new Set()});
   group.scans++;if(row.status==='Completed')group.completed++;const ref=safeRef(row.reference);if(ref)group.references.add(ref);
   for(const target of Array.isArray(row.targets)?row.targets:[])group.targets.add(safeTarget(target));
  }
  return {id:company.id,name:company.name,state:'needs-review',
   savedDefenderConnection:application.defender.some(d=>d.companyId===company.id),
   completedSpotlightPointer:application.spotlight.some(s=>s.companyId===company.id&&s.status==='completed'),
   scanners:[...groups.values()].map(g=>({...g,references:[...g.references],targets:[...g.targets].sort()})),
   inventory:inventory.filter(r=>r.company_id===company.id).map(r=>({source:r.source,count:r.count})),
   savedTiles:saved.tiles.filter(t=>t.companyId===company.id).map(t=>({id:t.id,source:t.source}))};
 });
 const report={collectedAt:new Date().toISOString(),mode:'proposed-assignment-review',recordedScans:rows.length,companies,
  unassignedTiles:saved.tiles.filter(t=>!t.companyId).map(t=>({id:t.id,source:t.source})),
  limitations:['Recorded scanner scope is historical evidence, not proof of current permission or tenant ownership.',
   'URL targets are shown as origins only; paths, queries and credentials are omitted. Review exact scope in the scanner before activation.',
   'No finding populations were scanned. Inventory counts do not establish vulnerability coverage.',
   'Configuration and record collections use separate read-only snapshots; recollect before applying approvals.',
   'No assignments, imports, scans, tickets, settings or schemas were changed.']};
 await writeFile(resolve(args[3]),JSON.stringify(report,null,2)+'\n',{mode:0o600,flag:'wx'});
 console.log(JSON.stringify({companies:companies.length,recordedScans:rows.length,unassignedTiles:report.unassignedTiles.length,changes:0}));
}finally{for(const c of clients)await c.end().catch(()=>{});}
