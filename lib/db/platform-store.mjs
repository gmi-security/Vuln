import {randomUUID,createHash} from 'node:crypto';
import {platformCollections,platformJson,platformHash,platformRecord,platformRecordOrders,upsertPlatformRecords} from './platform-records.mjs';
import {readPlatformAuthority,bindPlatformWriter,platformMetadata} from './platform-authority.mjs';
const check=(ok,message)=>{if(!ok)throw Error(message);};
const pause=()=>new Promise(resolve=>setImmediate(resolve));
const key=(kind,bucket)=>`${kind}:${String(bucket).padStart(2,'0')}`;
export const platformBucketKeys=Object.entries(platformCollections).flatMap(([kind,c])=>Array.from({length:c.buckets},(_,i)=>key(kind,i))).sort();
const metaOf=data=>Object.fromEntries(Object.entries(data).filter(([k])=>!platformCollections[k]));
const emptyIndex=()=>new Map(Object.keys(platformCollections).map(k=>[k,new Map()]));
// Large, explicitly scoped publications include many indexed row writes and
// reporting digests in one atomic commit. Keep ordinary edits at five minutes.
export const platformSaveTimeoutMs=changes=>changes?.findings?.length>=100000?900000:300000;
async function audit(client,authority,operation,actor,counts) {
 check(typeof actor==='string'&&actor.length>0&&actor.length<=160,'Explicit platform writer identity required');
 await client.query('INSERT INTO app_store_commits(id,epoch,revision,operation,actor,counts) VALUES($1,$2,$3,$4,$5,$6)',
  [randomUUID(),authority.epoch,authority.revision,operation,actor,JSON.stringify(counts)]);
}
export async function* platformBucketRows(client,kind,bucket,{companyId}={}) {
 const config=platformCollections[kind];check(config&&Number.isInteger(bucket)&&bucket>=0&&bucket<config.buckets,'Invalid platform bucket');
 let after=-1,afterId='';
 for(;;){
  const {rows}=await client.query(`SELECT id,payload,record_hash,store_order FROM ${config.table}
   WHERE store_bucket=$1 AND (store_order,id)>($2::double precision,$3::text) ${companyId===undefined?'':'AND company_id=$4'}
   ORDER BY store_order,id LIMIT 500`,companyId===undefined?[bucket,after,afterId]:[bucket,after,afterId,companyId]);
  if(!rows.length)return;
  for(const row of rows)yield row;
  after=rows.at(-1).store_order;afterId=rows.at(-1).id;await pause();
 }
}
// Compatible in-memory consumers hydrate once; SQL reports stream a customer
// directly. Hash/order state contains no second full copy of provider payloads.
export async function loadPlatformStore(client,authority) {
 check(authority?.mode==='sql','SQL platform authority required');
 const data=await platformMetadata(client,authority),index=emptyIndex();
 check(!Object.keys(platformCollections).some(k=>k in data),'Unsupported collection override');
 const metaHash=platformHash(platformJson(data));
 check((await client.query('SELECT record_hash FROM app_store_metadata WHERE id=1')).rows[0]?.record_hash===metaHash,'Platform metadata checksum mismatch');
 for(const [kind,config] of Object.entries(platformCollections)){
  data[kind]=[];
  for(let b=0;b<config.buckets;b++)for await(const row of platformBucketRows(client,kind,b)){
   const record=platformRecord(kind,[row.id,row.payload],row.store_order);
   check(record.record_hash===row.record_hash&&record.store_bucket===b,'Platform record checksum or bucket mismatch');
   data[kind].push([row.id,row.payload]);index.get(kind).set(row.id,{hash:row.record_hash,order:row.store_order,bucket:b});
  }
 }
 return {data,state:{authority,index,metaHash}};
}

// The application owns the single mutation queue. guard() rejects a capture
// changed while batches were prepared; the entire transaction then rolls back.
/**
 * @param {any} client
 * @param {Record<string, any>} data
 * @param {any} state
 * @param {{actor?: string, guard?: () => void, reporting?: ReturnType<import('./customer-reporting-revisions.mjs').createReportingInputDigests>}} options
 */
export async function savePlatformStore(client,data,state,{actor='application',guard=()=>{},reporting}={}) {
 check(state?.authority?.mode==='sql'&&data&&typeof data==='object','Loaded SQL writer required');
 await bindPlatformWriter(client,state.authority);
 const index=emptyIndex(),changedKeys=new Set(),counts={inserted:0,updated:0,deleted:0,metadata:0};
 const meta=metaOf(data),metaJson=platformJson(meta),metaHash=platformHash(metaJson);
 for(const [kind,config] of Object.entries(platformCollections)){
  check(Array.isArray(data[kind]),'Complete platform collections required');
  const grouped=Array.from({length:config.buckets},()=>[]),seen=new Set();
  // Partition identities only. Freeze each bounded bucket once below.
  for(const entry of data[kind]){
   check(Array.isArray(entry)&&typeof entry[0]==='string'&&!seen.has(entry[0]),'Invalid or duplicate platform identity');seen.add(entry[0]);
   const b=config.buckets===1?0:createHash('sha1').update(entry[0]).digest().readUInt32BE(0)%config.buckets;grouped[b].push(entry);
  }
  const prior=state.index.get(kind);
  for(let b=0;b<config.buckets;b++){
   const entries=grouped[b],orders=platformRecordOrders(entries,prior);let batch=[];
   // Reporting hashes the same frozen payloads that are written, including
   // unchanged records. It must never certify a different RAM generation.
   const frozen=[];
   for(let i=0;i<entries.length;i++){
    const r=platformRecord(kind,entries[i],orders[i]),old=prior.get(r.id);
    index.get(kind).set(r.id,{hash:r.record_hash,order:r.store_order,bucket:b});frozen.push([r.id,r.payload]);
    if(!old||old.hash!==r.record_hash||old.order!==r.store_order){batch.push(r);counts[old?'updated':'inserted']++;changedKeys.add(key(kind,b));}
    if(batch.length===500){await upsertPlatformRecords(client,kind,batch);batch=[];await pause();}
   }
   await upsertPlatformRecords(client,kind,batch);
   await reporting?.bucket(key(kind,b),JSON.stringify(frozen));await pause();await guard();
  }
  const deleted=[...prior.keys()].filter(id=>!seen.has(id));counts.deleted+=deleted.length;
  for(const id of deleted)changedKeys.add(key(kind,prior.get(id).bucket));
  for(let i=0;i<deleted.length;i+=500)await client.query(`DELETE FROM ${config.table} WHERE id=ANY($1::text[])`,[deleted.slice(i,i+500)]);
 }
 if(metaHash!==state.metaHash){await client.query(`INSERT INTO app_store_metadata(id,payload,record_hash) VALUES(1,$1,$2)
  ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload,record_hash=EXCLUDED.record_hash`,[metaJson,metaHash]);counts.metadata=1;changedKeys.add('meta');}
 await reporting?.bucket('meta',metaJson);await guard();
 let authority=state.authority;
 if(Object.values(counts).some(Boolean)){
  authority=(await client.query('UPDATE app_store_authority SET revision=revision+1,updated_at=clock_timestamp() WHERE id=1 RETURNING mode,enforced,epoch::text,revision::text')).rows[0];
  await audit(client,authority,'save',actor,{...counts,changedKeys:[...changedKeys].sort()});
 }
 return {authority,index,metaHash,counts};
}

// Explicit mutation scopes are supplied only by audited store operations.
// Unscoped imports/reconciliation retain the complete comparison path above.
// A scope includes deletions (an ID absent from the supplied partial collection).
export async function savePlatformDelta(client,data,state,changes,{guard=()=>{},actor='application'}={}){
 check(state?.authority?.mode==='sql'&&changes&&typeof changes==='object','Loaded SQL delta writer required');
 await bindPlatformWriter(client,state.authority);
 const index=new Map(state.index),changedKeys=new Set(),counts={inserted:0,updated:0,deleted:0,metadata:0};
 for(const [kind,ids]of Object.entries(changes)){
  const config=platformCollections[kind];check(config&&Array.isArray(ids)&&ids.every(id=>typeof id==='string'&&id.length>0)&&new Set(ids).size===ids.length,'Invalid platform mutation scope');
  const incoming=new Map(data[kind]),previous=state.index.get(kind),next=new Map(previous);index.set(kind,next);let batch=[];
  // bindPlatformWriter fenced this complete, committed index above. Allocate
  // append positions once per bucket, not with a SELECT + forced one-row flush
  // for every new finding in a bulk import.
  const appendOrders=new Map();
  for(const old of previous.values())appendOrders.set(old.bucket,Math.max(appendOrders.get(old.bucket)??0,old.order));
  for(const id of ids){
   const value=incoming.get(id),old=previous.get(id);
   if(value===undefined){if(old){await client.query(`DELETE FROM ${config.table} WHERE id=$1`,[id]);next.delete(id);counts.deleted++;changedKeys.add(key(kind,old.bucket));}continue;}
   let order=old?.order;
   if(order===undefined){
    const b=config.buckets===1?0:createHash('sha1').update(id).digest().readUInt32BE(0)%config.buckets;
    order=(appendOrders.get(b)??0)+1024;appendOrders.set(b,order);
   }
   const r=platformRecord(kind,[id,value],order);
   if(!old||r.record_hash!==old.hash){batch.push(r);counts[old?'updated':'inserted']++;changedKeys.add(key(kind,r.store_bucket));}
   next.set(id,{hash:r.record_hash,order:r.store_order,bucket:r.store_bucket});
   if(batch.length===500){await upsertPlatformRecords(client,kind,batch);batch=[];await pause();await guard();}
  }
  await upsertPlatformRecords(client,kind,batch);
 }
 const json=platformJson(metaOf(data)),metaHash=platformHash(json);
 if(metaHash!==state.metaHash){await client.query('UPDATE app_store_metadata SET payload=$1,record_hash=$2 WHERE id=1',[json,metaHash]);counts.metadata=1;changedKeys.add('meta');}
 await guard();let authority=state.authority;
 if(Object.values(counts).some(Boolean)){
  authority=(await client.query('UPDATE app_store_authority SET revision=revision+1,updated_at=clock_timestamp() WHERE id=1 RETURNING mode,enforced,epoch::text,revision::text')).rows[0];
  await audit(client,authority,'save',actor,{...counts,changedKeys:[...changedKeys].sort()});
 }
 return {authority,index,metaHash,counts,changedKeys:[...changedKeys]};
}

// Maintenance transitions run inside ONE caller-owned transaction while all
// application writers are stopped. Failure leaves the prior authority intact.
export async function transitionPlatformStore(client,direction,expected,{actor,reporting,checkpoint}={}) {
 check(direction==='sql'||direction==='legacy','Invalid platform transition');
 check(expected?.mode===(direction==='sql'?'legacy':'sql'),'Transition requires opposite current authority');
 await bindPlatformWriter(client,expected,direction==='sql'?'backfill':'reverse');
 await client.query('LOCK TABLE public.vuln_store IN SHARE ROW EXCLUSIVE MODE');
 const counts={};
 if(direction==='sql'){
  const keys=(await client.query('SELECT key FROM vuln_store ORDER BY key')).rows.map(r=>r.key);
  check(JSON.stringify(keys)===JSON.stringify([...platformBucketKeys,'meta'].sort()),'Complete canonical legacy snapshot required');
  const meta=await platformMetadata(client,expected);check(!Object.keys(platformCollections).some(k=>k in meta),'Unsupported snapshot collection override');
  for(const [kind,config] of Object.entries(platformCollections)){
   await client.query(`DELETE FROM ${config.table}`);counts[kind]=0;
   for(let b=0;b<config.buckets;b++){
    const entries=(await client.query('SELECT data FROM vuln_store WHERE key=$1',[key(kind,b)])).rows[0].data;
    check(Array.isArray(entries),'Invalid legacy collection');let batch=[];const hashes=[];
    for(let i=0;i<entries.length;i++){
     const r=platformRecord(kind,entries[i],(i+1)*1024);check(r.store_bucket===b,'Legacy record is in wrong bucket');
     // Duplicate identities must fail instead of letting UPSERT discard one.
     hashes.push([r.id,r.record_hash]);batch.push(r);
     if(batch.length===500){await upsertPlatformRecords(client,kind,batch);batch=[];}
    }
    check(new Set(hashes.map(r=>r[0])).size===hashes.length,'Duplicate legacy identity');
    await upsertPlatformRecords(client,kind,batch);
    const copied=[];for await(const r of platformBucketRows(client,kind,b))copied.push([r.id,platformHash(platformJson(r.payload))]);
    check(JSON.stringify(copied)===JSON.stringify(hashes),'Platform backfill parity failed');
    counts[kind]+=entries.length;await reporting?.bucket(key(kind,b),JSON.stringify(entries));await checkpoint?.({kind,bucket:b});
   }
  }
  const json=platformJson(meta);await client.query(`INSERT INTO app_store_metadata(id,payload,record_hash) VALUES(1,$1,$2)
   ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload,record_hash=EXCLUDED.record_hash`,[json,platformHash(json)]);
  await reporting?.bucket('meta',json);
 }else{
  const meta=await platformMetadata(client,expected),json=platformJson(meta);
  check(platformHash(json)===(await client.query('SELECT record_hash FROM app_store_metadata WHERE id=1')).rows[0]?.record_hash,'Platform metadata checksum mismatch');
  for(const [kind,config] of Object.entries(platformCollections)){
   counts[kind]=0;
   for(let b=0;b<config.buckets;b++){
    const entries=[];
    for await(const row of platformBucketRows(client,kind,b)){
     const r=platformRecord(kind,[row.id,row.payload],row.store_order);
     check(r.record_hash===row.record_hash&&r.store_bucket===b,'Platform reverse checksum mismatch');entries.push([row.id,row.payload]);
    }
    counts[kind]+=entries.length;const json=JSON.stringify(entries);
    await client.query('INSERT INTO vuln_store(key,data,updated_at) VALUES($1,$2,clock_timestamp()) ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data,updated_at=EXCLUDED.updated_at',[key(kind,b),json]);
    await reporting?.bucket(key(kind,b),json);await checkpoint?.({kind,bucket:b});
   }
  }
  await client.query("UPDATE vuln_store SET data=$1,updated_at=clock_timestamp() WHERE key='meta'",[json]);
  await reporting?.bucket('meta',json);
 }
 const authority=(await client.query('UPDATE app_store_authority SET mode=$1,enforced=true,epoch=epoch+1,revision=0,updated_at=clock_timestamp() WHERE id=1 RETURNING mode,enforced,epoch::text,revision::text',[direction])).rows[0];
 await audit(client,authority,direction==='sql'?'backfill':'reverse',actor,counts);
 return {authority,counts};
}
