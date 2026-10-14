import {createHash} from 'node:crypto';

// The existing normalized Finding/Company/Scan/Asset shapes remain the adapter
// contract. Provider-specific evidence stays in payload; indexed columns expose
// the common fields without copying raw vendor generations into another model.
export const platformCollections=Object.freeze({companies:{table:'app_companies',buckets:1},folders:{table:'app_folders',buckets:1},
 scans:{table:'app_scans',buckets:8},findings:{table:'app_findings',buckets:64},assets:{table:'app_assets',buckets:16}});
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?
 Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
export function platformJson(value){return JSON.stringify(canonical(JSON.parse(JSON.stringify(value))));}
export const platformHash=json=>createHash('sha256').update(json).digest('hex');
export function platformBucket(id,count){return count===1?0:createHash('sha1').update(id).digest().readUInt32BE(0)%count;}
const text=value=>typeof value==='string'?value:null;
const time=value=>typeof value==='string'&&Number.isFinite(Date.parse(value))?new Date(value).toISOString():null;
export function platformRecord(kind,entry,order){
 const config=platformCollections[kind];requireValue(config,'Unknown platform collection');
 requireValue(Array.isArray(entry)&&entry.length===2&&typeof entry[0]==='string'&&entry[0].length>0&&entry[0].length<=512&&
  entry[1]&&typeof entry[1]==='object'&&!Array.isArray(entry[1])&&entry[1].id===entry[0],'Invalid platform record identity');
 requireValue(Number.isFinite(order)&&order>=0&&order<Number.MAX_SAFE_INTEGER,'Invalid platform record order');
 // Freeze the exact payload being hashed before yielding to another writer.
 const json=platformJson(entry[1]);requireValue(Buffer.byteLength(json)<=16*1024*1024,'Platform record exceeds 16 MiB');
 const p=JSON.parse(json),base={id:entry[0],payload:p,record_hash:platformHash(json),store_order:order,store_bucket:platformBucket(entry[0],config.buckets)};
 const fields=kind==='companies'?{name:text(p.name),kind:['client','internal'].includes(p.kind)?p.kind:null,created_at:time(p.createdAt)}:
  kind==='folders'?{company_id:text(p.companyId),name:text(p.name),created_at:time(p.createdAt)}:
  kind==='scans'?{company_id:text(p.companyId),folder_id:text(p.folderId),connector:text(p.connector),status:text(p.status),external_ref:text(p.externalRef),created_at:time(p.createdAt)}:
  kind==='findings'?{company_id:text(p.companyId),scan_id:text(p.scanId),connector:text(p.connector),status:text(p.status),severity:text(p.severity),cve:text(p.cve),asset:text(p.asset),real_risk:Number.isFinite(p.realRisk)?p.realRisk:null,last_seen:time(p.lastSeen)}:
  {company_id:text(p.companyId),identifier:text(p.identifier),source:text(p.source),external_id:text(p.externalId),last_synced:time(p.lastSynced)};
 return {...base,...fields};
}

// Leave holes after deletions and allocate gaps for new records. A single delete
// must not rewrite every later record. A deliberate Map reorder rebalances the
// order keys; payloads and identities remain unchanged.
export function platformRecordOrders(entries,previous=new Map()){
 const ids=new Set();let last=-1,reordered=false;
 for(const [id] of entries){requireValue(!ids.has(id),'Duplicate platform record');ids.add(id);const old=previous.get(id);
  if(old){if(old.order<=last)reordered=true;last=old.order;}}
 if(reordered)return entries.map((_,i)=>(i+1)*1024);
 const following=new Array(entries.length);let next=Infinity;
 for(let i=entries.length-1;i>=0;i--){following[i]=next;const old=previous.get(entries[i][0]);if(old)next=old.order;}
 const orders=[];let prior=0;
 for(let i=0;i<entries.length;i++){
  const old=previous.get(entries[i][0]);const order=old?old.order:Number.isFinite(following[i])?(prior+following[i])/2:prior+1024;
  if(order<=prior||order>=Number.MAX_SAFE_INTEGER)return entries.map((_,j)=>(j+1)*1024);
  orders.push(order);prior=order;
 }
 return orders;
}

const columnTypes={id:'text',payload:'jsonb',record_hash:'text',store_order:'double precision',store_bucket:'integer',
 name:'text',kind:'text',created_at:'timestamptz',company_id:'text',folder_id:'text',connector:'text',status:'text',external_ref:'text',
 scan_id:'text',severity:'text',cve:'text',asset:'text',real_risk:'double precision',last_seen:'timestamptz',identifier:'text',source:'text',external_id:'text',last_synced:'timestamptz'};
export async function upsertPlatformRecords(client,kind,records){
 requireValue(platformCollections[kind]&&Array.isArray(records)&&records.length<=500,'Invalid platform write batch');if(!records.length)return;
 const names=Object.keys(records[0]);requireValue(names.every(k=>columnTypes[k])&&records.every(r=>Object.keys(r).join(',')===names.join(',')),'Invalid platform column shape');
 await client.query(`INSERT INTO ${platformCollections[kind].table}(${names.join(',')}) SELECT ${names.join(',')} FROM jsonb_to_recordset($1::jsonb) AS r(${names.map(k=>`${k} ${columnTypes[k]}`).join(',')})
  ON CONFLICT(id) DO UPDATE SET ${names.filter(k=>k!=='id').map(k=>`${k}=EXCLUDED.${k}`).join(',')}`,[JSON.stringify(records)]);
}
