// Version of the persisted inputs consumed by the report-sections model.
// Updating report input fields requires a version bump and fresh publication.
import {createHash,randomUUID} from 'node:crypto';
import {readPlatformAuthority} from './platform-authority.mjs';
import {platformCollections} from './platform-records.mjs';
export const REPORT_INPUT_VERSION=3;
export const reportingFields={
 findings:['id','companyId','connector','seenBy','enrichments','cve','title','asset','severity','cvss','realRisk','status','lastSeen','kev','exploitAvailable','assetSource',
  'firstSeen','resolvedAt','cvssV2','cvssV3','epss','category','assetExposure','assetCriticality','ransomware'],
 scans:['id','companyId','name','connector','status','createdAt','completedAt','findingsCount','hostsScanned'],
 assets:['id','companyId','identifier','source','lastSynced','hostname','ipAddresses'],
};
export const reportingKeys=['meta','companies:00',...['findings','scans','assets'].flatMap(name=>
 Array.from({length:name==='findings'?64:name==='scans'?8:16},(_,i)=>`${name}:${String(i).padStart(2,'0')}`))].sort();
const canonical=value=>value instanceof Date?value.toISOString():Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?
 Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
export const reportingDigest=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};

// Feed the exact JSON serialized for persistence, not live mutable store objects.
// Only a bucket is parsed at a time. Other customers and bookkeeping do not
// change this customer's digest. Relative order within a bucket is significant.
export function createReportingInputDigests(cache=new Map()){
 const pending=new Map();
 return {
  async bucket(key,json,serializedHash){
   if(!reportingKeys.includes(key))return;
   requireValue(!pending.has(key),'Duplicate reporting publication bucket');
   const checksum=serializedHash??createHash('sha1').update(json).digest('hex');
   if(cache.get(key)?.checksum===checksum){pending.set(key,cache.get(key));return;}
   const rows=JSON.parse(json),kind=key.split(':')[0],hashes=new Map(),owners=[];
   const add=(id,value)=>{
    requireValue(typeof id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(id),'Invalid reporting publication customer');
    if(!hashes.has(id)){requireValue(hashes.size<10000,'Too many reporting customers');hashes.set(id,createHash('sha256'));}
    hashes.get(id).update(JSON.stringify(canonical(value))+'\n');
   };
   if(key==='meta'){
    requireValue(rows&&typeof rows==='object'&&!Array.isArray(rows)&&!['companies','findings','scans','assets'].some(k=>k in rows),'Unsupported reporting snapshot overrides');
   }else{
    requireValue(Array.isArray(rows),'Invalid reporting publication bucket');let count=0;
    for(const entry of rows){
     requireValue(Array.isArray(entry)&&entry.length===2&&typeof entry[0]==='string'&&entry[1]?.id===entry[0],'Invalid reporting publication identity');
     const r=entry[1];
     if(kind==='companies'){
      requireValue(!hashes.has(r.id)&&typeof r.name==='string'&&r.name.length>0&&(r.isDemo===undefined||r.isDemo===null||typeof r.isDemo==='boolean'),'Invalid reporting publication company');
      owners.push(r.id);add(r.id,{id:r.id,name:r.name,industry:r.industry,isDemo:r.isDemo===true});
     }else add(r.companyId,Object.fromEntries(reportingFields[kind].filter(k=>r[k]!=null).map(k=>[k,r[k]])));
     if(++count%2000===0)await new Promise(resolve=>setImmediate(resolve));
    }
   }
   pending.set(key,{checksum,owners,pieces:[...hashes].map(([id,hash])=>[id,hash.digest('hex')])});
  },
  finish(){
   requireValue(pending.size===reportingKeys.length,'Incomplete reporting publication');
   const owners=new Set(pending.get('companies:00').owners),parts=new Map();
   for(const key of reportingKeys)for(const [id,digest] of pending.get(key).pieces){
    requireValue(owners.has(id),'Reporting record has no saved customer');
    if(!parts.has(id))parts.set(id,[]);parts.get(id).push([key,digest]);
   }
   return [...parts].sort(([a],[b])=>a.localeCompare(b)).map(([companyId,pieces])=>({companyId,hash:reportingDigest(pieces),buckets:pieces}));
  },
  committed(){cache.clear();for(const [key,part] of pending)cache.set(key,part);},
 };
}
export async function reportingSnapshotManifest(client){
 const authority=await readPlatformAuthority(client);
 if(authority?.mode==='sql'){
  const {rows:[identity]}=await client.query("SELECT current_database() db,'public.app_store_authority'::regclass::oid::text relation");
  return {identity,hash:reportingDigest({identity,authority})};
 }
 const {rows}=await client.query('SELECT key,xmin::text AS revision FROM public.vuln_store WHERE key=ANY($1::text[]) ORDER BY key',[reportingKeys]);
 requireValue(rows.length===reportingKeys.length&&rows.every((r,i)=>r.key===reportingKeys[i]),'Complete reporting snapshot required');
 const {rows:[identity]}=await client.query("SELECT current_database() db,'public.vuln_store'::regclass::oid::text relation");
 return {identity,hash:reportingDigest({identity,rows})};
}
// Caller owns the SAME transaction that saves all snapshot shards. No DDL,
// startup migration, new authoritative store, or external writes happen here.
export async function publishReportingInputRevisions(client,digests){
 const {rows:[lock]}=await client.query('SELECT pg_try_advisory_xact_lock(804260,1) acquired');
 requireValue(lock.acquired,'Reporting publication busy');
 const ids=digests.map(d=>d.companyId);
 for(const row of digests)await client.query(`INSERT INTO public.customer_reporting_inputs(company_id,format_version,revision,generation,content_hash,bucket_map)
  VALUES($1,$2,1,$3,$4,$5) ON CONFLICT(company_id) DO UPDATE SET format_version=EXCLUDED.format_version,
  revision=customer_reporting_inputs.revision+1,generation=EXCLUDED.generation,content_hash=EXCLUDED.content_hash,bucket_map=EXCLUDED.bucket_map,published_at=clock_timestamp()
  WHERE customer_reporting_inputs.format_version<>EXCLUDED.format_version OR customer_reporting_inputs.content_hash<>EXCLUDED.content_hash
   OR customer_reporting_inputs.bucket_map IS DISTINCT FROM EXCLUDED.bucket_map`,
  [row.companyId,REPORT_INPUT_VERSION,randomUUID(),row.hash,JSON.stringify(row.buckets)]);
 await client.query('DELETE FROM public.customer_reporting_inputs WHERE NOT(company_id=ANY($1::text[]))',[ids]);
 const manifest=await reportingSnapshotManifest(client);
 await client.query(`INSERT INTO public.customer_reporting_publication(id,format_version,manifest_hash) VALUES(1,$1,$2)
  ON CONFLICT(id) DO UPDATE SET format_version=EXCLUDED.format_version,manifest_hash=EXCLUDED.manifest_hash,published_at=clock_timestamp()`,[REPORT_INPUT_VERSION,manifest.hash]);
 return manifest.hash;
}
export async function readReportingInputRevision(client,companyId){
 const manifest=await reportingSnapshotManifest(client);
 const {rows:[row]}=await client.query(`SELECT i.revision::text,i.generation,i.content_hash,i.format_version,i.bucket_map,p.manifest_hash,p.format_version AS publication_version
  FROM public.customer_reporting_inputs i CROSS JOIN public.customer_reporting_publication p WHERE i.company_id=$1 AND p.id=1`,[companyId]);
 requireValue(row?.format_version===REPORT_INPUT_VERSION&&row.publication_version===REPORT_INPUT_VERSION&&row.manifest_hash===manifest.hash,
  'Reporting publication is missing or no longer matches the saved platform data');
 requireValue(Array.isArray(row.bucket_map)&&row.bucket_map.length>=1&&row.bucket_map.length<=89&&
  row.bucket_map.every(p=>Array.isArray(p)&&p.length===2&&reportingKeys.includes(p[0])&&p[0]!=='meta'&&typeof p[1]==='string'&&/^[a-f0-9]{64}$/.test(p[1]))&&
  new Set(row.bucket_map.map(p=>p[0])).size===row.bucket_map.length&&row.bucket_map.some(p=>p[0]==='companies:00')&&
  reportingDigest(row.bucket_map)===row.content_hash,'Invalid customer reporting bucket map');
 return {identity:manifest.identity,revision:row.revision,generation:row.generation,hash:row.content_hash,buckets:row.bucket_map.map(p=>p[0]).sort()};
}

// A precise row edit only invalidates the reporting pieces for touched buckets.
// Read thin projected fields from SQL; never serialize unrelated vendor payloads.
// The caller owns the same transaction as the row and authority revision update.
export async function collectSqlReportingTargets(client,plan){
 // Company additions/removals change ownership itself: retain full validation.
 if(plan.changedKeys.includes('companies:00'))return undefined;
 const targets=new Map();let complete=true;
 const add=(kind,row)=>{
  if(typeof row.company_id!=='string'||!row.company_id){complete=false;return;}
  const key=`${kind}:${String(row.store_bucket).padStart(2,'0')}`;
  if(!targets.has(key))targets.set(key,new Set());targets.get(key).add(row.company_id);
 };
 for(const kind of Object.keys(reportingFields)){
  const writes=plan.writes.get(kind)??[],deleted=plan.deletes.get(kind)??[];
  const ids=[...writes.map(r=>r.id),...deleted];
  // Run under the writer fence BEFORE deleting/reassigning rows, so both sides
  // of an ownership move (and the last deleted row) invalidate their reports.
  for(let i=0;i<ids.length;i+=500){
   const {rows}=await client.query(`SELECT id,company_id,store_bucket FROM ${platformCollections[kind].table} WHERE id=ANY($1::text[])`,[ids.slice(i,i+500)]);
   for(const row of rows)add(kind,row);
  }
  for(const row of writes)add(kind,row);
 }
 if(!complete||plan.changedKeys.some(k=>reportingKeys.includes(k)&&k!=='meta'&&!targets.has(k)))return undefined;
 return Object.fromEntries([...targets].map(([key,ids])=>[key,[...ids].sort()]));
}

export async function publishSqlReportingChanges(client,changedKeys,targets,prepared){
 // These are the detached rows just written in THIS transaction, never live
 // store objects. Group references once; only one bucket gets an ID lookup.
 // Small edits retain the single-query reader to avoid extra round trips.
 const frozenBuckets=new Map();
 for(const kind of Object.keys(reportingFields))for(const row of prepared?.writes?.get(kind)??[]){
  const key=`${kind}:${String(row.store_bucket).padStart(2,'0')}`;
  if(!frozenBuckets.has(key))frozenBuckets.set(key,[]);
  frozenBuckets.get(key).push(row);
 }
 const current=(await client.query('SELECT company_id,format_version,bucket_map,content_hash FROM customer_reporting_inputs ORDER BY company_id')).rows;
 requireValue(current.length<=10000&&current.every(r=>r.format_version===REPORT_INPUT_VERSION&&Array.isArray(r.bucket_map)&&
  r.bucket_map.every(p=>Array.isArray(p)&&p.length===2&&reportingKeys.includes(p[0])&&p[0]!=='meta'&&/^[a-f0-9]{64}$/.test(p[1]))&&
  new Set(r.bucket_map.map(p=>p[0])).size===r.bucket_map.length&&reportingDigest(r.bucket_map)===r.content_hash), 'Current reporting input maps required');
 const parts=new Map(current.map(r=>[r.company_id,new Map(r.bucket_map)]));
 const companies=(await client.query('SELECT id FROM app_companies ORDER BY id')).rows.map(r=>r.id),owners=new Set(companies);
 for(const id of companies)if(!parts.has(id))parts.set(id,new Map());
 for(const id of parts.keys())if(!owners.has(id))parts.delete(id);
 for(const key of [...new Set(changedKeys)].filter(k=>reportingKeys.includes(k)&&k!=='meta').sort()){
  const [kind,rawBucket]=key.split(':'),config=platformCollections[kind];requireValue(config,'Invalid reporting delta collection');
  const selected=targets===undefined?undefined:targets[key];
  requireValue(selected===undefined&&targets===undefined||Array.isArray(selected)&&selected.length>0&&selected.every(id=>owners.has(id)), 'Invalid reporting customer scope');
  for(const [id,pieces] of parts)if(selected===undefined||selected.includes(id))pieces.delete(key);
  const frozenRows=frozenBuckets.get(key);
  const frozen=frozenRows?.length>=500?new Map(frozenRows.map(r=>[r.id,r.payload])):undefined;
  const hashes=new Map();
  // Equality on one customer lets PostgreSQL seek the customer/order index.
  // ANY used the global order index and reread unrelated heap rows per page.
  for(const companyId of new Set(selected??[undefined])){
  let order=-1,last='';
  for(;;){
   const projection=kind==='companies'?'payload':`jsonb_build_object(${reportingFields[kind].flatMap(k=>[`'${k}'`,`payload->'${k}'`]).join(',')})`;
   const {rows}=await client.query(`SELECT id,store_order${frozen?'':`,${projection} record`} FROM ${config.table}
    WHERE store_bucket=$1 AND (store_order,id)>($2::double precision,$3::text) ${companyId===undefined?'':'AND company_id=$4'} ORDER BY store_order,id LIMIT 500`,
    companyId===undefined?[Number(rawBucket),order,last]:[Number(rawBucket),order,last,companyId]);
   if(!rows.length)break;
   if(frozen){
    // SQL still decides membership and ordering (including equal-order IDs).
    // Only unchanged records need their reporting fields fetched again. Keep
    // each response bounded to a page, without copying the whole import.
    const missing=rows.filter(r=>!frozen.has(r.id)).map(r=>r.id);
    const saved=missing.length?new Map((await client.query(`SELECT id,${projection} record FROM ${config.table} WHERE id=ANY($1::text[])`,[missing])).rows.map(r=>[r.id,r.record])):new Map();
    for(const row of rows){
     row.record=frozen.get(row.id)??saved.get(row.id);
     requireValue(row.record?.id===row.id,'Reporting record missing from committed preparation');
    }
   }
   for(const {record:r} of rows){
    const id=kind==='companies'?r.id:r.companyId;requireValue(owners.has(id),'Reporting record has no saved customer');
    if(!hashes.has(id))hashes.set(id,createHash('sha256'));
    const value=kind==='companies'?{id:r.id,name:r.name,industry:r.industry,isDemo:r.isDemo===true}:
     Object.fromEntries(reportingFields[kind].filter(k=>r[k]!=null).map(k=>[k,r[k]]));
    hashes.get(id).update(JSON.stringify(canonical(value))+'\n');
   }
   order=rows.at(-1).store_order;last=rows.at(-1).id;
  }
  }
  for(const [id,hash] of hashes)parts.get(id).set(key,hash.digest('hex'));
 }
 const digests=[...parts].sort(([a],[b])=>a.localeCompare(b)).map(([companyId,entries])=>{
  const buckets=[...entries].sort(([a],[b])=>a.localeCompare(b));
  requireValue(buckets.some(([k])=>k==='companies:00'),'Company reporting piece is missing');
  return {companyId,buckets,hash:reportingDigest(buckets)};
 });
 return publishReportingInputRevisions(client,digests);
}
