import {createHash} from 'node:crypto';
import {readPlatformAuthority} from './platform-authority.mjs';
import {platformJson} from './platform-records.mjs';

const hash=value=>createHash('sha256').update(value).digest('hex');
const quote=value=>'"'+value.replaceAll('"','""')+'"';
const kinds=['companies','folders','scans','findings','assets'];

export function relationshipSummary(rows){
 const byKind=Object.fromEntries(kinds.map(kind=>[kind,new Map(rows[kind]??[])]));
 let orphans=0,idMismatches=0,duplicateIds=0;
 for(const kind of kinds){
  const entries=rows[kind]??[];
  duplicateIds+=entries.length-byKind[kind].size;
  for(const [id,value] of entries)if(value?.id!==id)idMismatches++;
 }
 for(const [,folder] of byKind.folders)if(!byKind.companies.has(folder.companyId))orphans++;
 for(const [,scan] of byKind.scans){
  if(!byKind.companies.has(scan.companyId)||byKind.folders.get(scan.folderId)?.companyId!==scan.companyId)orphans++;
 }
 for(const [,finding] of byKind.findings)
  if(!byKind.companies.has(finding.companyId)||byKind.scans.get(finding.scanId)?.companyId!==finding.companyId)orphans++;
 for(const [,asset] of byKind.assets)if(!byKind.companies.has(asset.companyId))orphans++;
 return {orphans,idMismatches,duplicateIds,counts:Object.fromEntries(kinds.map(kind=>[kind,(rows[kind]??[]).length])),
  sourceCustomers:['CO-9150','CO-9153'].filter(id=>byKind.companies.has(id))};
}

export function compareEvidence(before,after){
 if(JSON.stringify(before)!==JSON.stringify(after))throw Error('Complete logical evidence changed.');
}

export function assertHistoricalParity(before,after){
 const buckets=evidence=>evidence.bucketHashes.filter(row=>row.key!=='meta');
 if(JSON.stringify(buckets(before))!==JSON.stringify(buckets(after)))
  throw Error('Historical customer buckets changed.');
 for(const name of ['patch_group_ticket_requests','patch_group_ticket_audit','vuln_metrics_history',
  'customer_consolidation_runs']){
  const old=before.tables.find(row=>row.name===name),current=after.tables.find(row=>row.name===name);
  if(!old||JSON.stringify(old)!==JSON.stringify(current))throw Error(`Historical table ${name} changed.`);
 }
}

// Caller owns a repeatable-read, read-only transaction. FETCH bounds Node memory.
export async function collectGate3Evidence(client){
 const schema=(await client.query(`SELECT c.relname table_name,a.attnum,a.attname,
  format_type(a.atttypid,a.atttypmod) data_type,a.attnotnull,
  pg_get_expr(d.adbin,d.adrelid) default_value
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
  LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
  WHERE n.nspname='public' AND c.relkind IN ('r','p','m') ORDER BY c.relname,a.attnum`)).rows;
 const constraints=(await client.query(`SELECT c.conrelid::regclass::text table_name,c.conname,
  c.contype,c.convalidated,pg_get_constraintdef(c.oid) definition
  FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
  WHERE n.nspname='public' ORDER BY c.conrelid::regclass::text,c.conname`)).rows;
 const indexes=(await client.query(`SELECT tablename,indexname,indexdef FROM pg_indexes
  WHERE schemaname='public' ORDER BY tablename,indexname`)).rows;
 const views=(await client.query(`SELECT viewname,definition FROM pg_views WHERE schemaname='public' ORDER BY viewname`)).rows;
 const sequences=(await client.query(`SELECT sequencename,data_type,start_value,min_value,max_value,increment,cycle,last_value
  FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename`)).rows;
 const triggers=(await client.query(`SELECT tgrelid::regclass::text table_name,tgname,pg_get_triggerdef(oid) definition
  FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN
  (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')
  ORDER BY tgrelid::regclass::text,tgname`)).rows;
 const routines=(await client.query(`SELECT p.proname,pg_get_function_identity_arguments(p.oid) arguments,
  pg_get_functiondef(p.oid) definition FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='public' AND p.prokind IN ('f','p') ORDER BY p.proname,arguments`)).rows;
 const tableNames=[...new Set(schema.map(row=>row.table_name))].sort();
  const tables=[],bucketHashes=[],relationshipsRows=Object.fromEntries(kinds.map(kind=>[kind,[]]));
  let aliases={count:0,legacySourcePrefixes:0,mappingsRecorded:false};
  const snapshotDigest=createHash('sha256');
 for(const name of tableNames){
  const keys=(await client.query(`SELECT a.attname FROM pg_index i
   JOIN pg_class t ON t.oid=i.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace
   JOIN unnest(i.indkey) WITH ORDINALITY k(attnum,ord) ON true
   JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum
   WHERE n.nspname='public' AND t.relname=$1 AND i.indisprimary ORDER BY k.ord`,[name])).rows.map(row=>row.attname);
  const order=keys.length?keys.map(key=>`t.${quote(key)}`).join(','):'to_jsonb(t)::text';
  await client.query(`DECLARE gate34_rows NO SCROLL CURSOR FOR SELECT to_jsonb(t)::text payload
   FROM public.${quote(name)} t ORDER BY ${order}`);
  const digest=createHash('sha256');let count=0;
  try{
   for(;;){
    const batch=(await client.query('FETCH FORWARD 32 FROM gate34_rows')).rows;
    if(!batch.length)break;
    for(const {payload} of batch){
     digest.update(payload);digest.update('\n');count++;
     if(name==='vuln_store'){
      const row=JSON.parse(payload);
      const canonical=platformJson(row.data);
      snapshotDigest.update(row.key);snapshotDigest.update('\0');
      snapshotDigest.update(canonical);snapshotDigest.update('\n');
      bucketHashes.push({key:row.key,sha256:hash(canonical)});
      if(row.key==='meta'){
       const entries=row.data?.identityAliases??[];
       aliases={count:entries.length,
        legacySourcePrefixes:entries.filter(([source])=>/^CO-(9150|9153)::/.test(source)).length,
        mappingsRecorded:JSON.stringify(row.data?.customerConsolidation?.mappings)===
         JSON.stringify([{sourceId:'CO-9150',destinationId:'CO-229336'},
          {sourceId:'CO-9153',destinationId:'CO-229438'}])};
      }
      const kind=row.key.split(':')[0];
      if(kinds.includes(kind))for(const [id,value] of row.data)
       relationshipsRows[kind].push([id,{id:value?.id,companyId:value?.companyId,
        folderId:value?.folderId,scanId:value?.scanId}]);
     }
    }
   }
  }finally{await client.query('CLOSE gate34_rows');}
  tables.push({name,count,sha256:digest.digest('hex')});
 }
 const relationships=relationshipSummary(relationshipsRows);
 const authority=await readPlatformAuthority(client);
 const hasLedger=(await client.query("SELECT to_regclass('public.customer_consolidation_runs')::text relation")).rows[0]?.relation;
 const ledger=hasLedger?(await client.query(`SELECT id,before_hash,after_hash,plan_hash,
  jsonb_array_length(lineage->'companies') company_lineage,
  jsonb_array_length(lineage->'scanExternalRefs') scan_reference_lineage,
  jsonb_array_length(lineage->'nessusOffsetLastTriggered') scheduler_lineage
  FROM customer_consolidation_runs ORDER BY id`)).rows:[];
 const invalidForeignKeys=constraints.filter(row=>row.contype==='f'&&!row.convalidated).map(row=>row.conname);
 const schemaSha256=hash(JSON.stringify({schema,constraints,indexes,views,sequences,triggers,routines}));
 const evidence={schemaSha256,tables,bucketHashes,snapshotSha256:snapshotDigest.digest('hex'),authority,ledger,
  relationships,aliases,invalidForeignKeys};
 return {...evidence,logicalSha256:hash(JSON.stringify(evidence))};
}
