// Version of the persisted inputs consumed by the report-sections model.
// Updating report input fields requires a version bump and fresh publication.
import {createHash,randomUUID} from 'node:crypto';
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
