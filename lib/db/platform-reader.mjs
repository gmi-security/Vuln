import {readPlatformAuthority,samePlatformAuthority} from './platform-authority.mjs';
import {platformCollections,platformJson,platformHash,platformRecord} from './platform-records.mjs';
import {platformBucketKeys,platformBucketRows} from './platform-store.mjs';

/** @typedef {readonly (readonly [string, Readonly<Record<string, any>>])[]} BucketRecords */
/**
 * @typedef {Readonly<{
 *  authority: Readonly<{mode: 'sql', enforced: true, epoch: string, revision: string}>,
 *  buckets: ReadonlyMap<string, BucketRecords>, metadata: Readonly<Record<string, any>>,
 *  changedKeys: readonly string[]
 * }>} CommittedPlatformSnapshot
 */
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const allKeys=Object.freeze([...platformBucketKeys,'meta'].sort());
const validKeys=new Set(allKeys);
const MAX_AUDIT_COMMITS=10000;
const decimal=value=>typeof value==='string'&&/^\d+$/.test(value);
const validAuthority=value=>value?.mode==='sql'&&value.enforced===true&&decimal(value.epoch)&&BigInt(value.epoch)>0n&&decimal(value.revision);

function freezeJson(value){
 if(value&&typeof value==='object'&&!Object.isFrozen(value)){
  for(const child of Object.values(value))freezeJson(child);
  Object.freeze(value);
 }
 return value;
}
/** @param {Iterable<readonly [string, BucketRecords]>} entries */
function immutableBuckets(entries){
 const map=new Map(entries),reject=()=>{throw Error('Committed platform buckets are immutable');};
 // Object.freeze(Map) alone does not prevent set/delete/clear.
 Object.defineProperties(map,{set:{value:reject},delete:{value:reject},clear:{value:reject}});
 return Object.freeze(map);
}
function usablePrevious(previous){
 return validAuthority(previous?.authority)&&previous.buckets instanceof Map&&previous.buckets.size===platformBucketKeys.length&&
  platformBucketKeys.every(key=>Array.isArray(previous.buckets.get(key)))&&previous.metadata&&typeof previous.metadata==='object';
}

// An audit without exact touched buckets can prove only a metadata-only edit.
// Invalid/incomplete history falls back to full verification, never a partial view.
async function changedSince(client,previous,authority){
 if(!previous||previous.authority.epoch!==authority.epoch)return null;
 const before=BigInt(previous.authority.revision),after=BigInt(authority.revision),distance=after-before;
 if(distance<=0n||distance>BigInt(MAX_AUDIT_COMMITS))return null;
 const {rows}=await client.query(`SELECT epoch::text,revision::text,operation,counts FROM app_store_commits
  WHERE epoch=$1 AND revision>$2 AND revision<=$3 ORDER BY revision LIMIT ${MAX_AUDIT_COMMITS+1}`,
 [authority.epoch,previous.authority.revision,authority.revision]);
 if(BigInt(rows.length)!==distance)return null;
 const changed=new Set();let revision=before;
 for(const row of rows){
  if(row.epoch!==authority.epoch||!decimal(row.revision)||BigInt(row.revision)!==++revision||row.operation!=='save')return null;
  const counts=row.counts;
  if(!counts||typeof counts!=='object'||Array.isArray(counts)||
   !['inserted','updated','deleted','metadata'].every(key=>Number.isSafeInteger(counts[key])&&counts[key]>=0)||counts.metadata>1)return null;
  const recordsChanged=counts.inserted>0||counts.updated>0||counts.deleted>0;
  if(!Object.hasOwn(counts,'changedKeys')){
   if(recordsChanged)return null;
   if(counts.metadata)changed.add('meta');
   continue;
  }
  const keys=counts.changedKeys;
  if(!Array.isArray(keys)||keys.some(key=>typeof key!=='string'||!validKeys.has(key))||new Set(keys).size!==keys.length||
   (counts.metadata&&!keys.includes('meta'))||(recordsChanged&&!keys.some(key=>key!=='meta')))return null;
  for(const key of keys)changed.add(key);
 }
 return [...changed].sort();
}

async function readMetadata(client){
 const row=(await client.query('SELECT payload,record_hash FROM app_store_metadata WHERE id=1')).rows[0];
 const value=row?.payload;
 requireValue(value&&typeof value==='object'&&!Array.isArray(value),'Missing platform metadata');
 requireValue(!Object.keys(platformCollections).some(key=>Object.hasOwn(value,key)),'Unsupported collection override');
 const json=platformJson(value),hash=platformHash(json);
 requireValue(hash===row.record_hash,'Platform metadata checksum mismatch');
 return {value:freezeJson(JSON.parse(json)),hash};
}

/** @returns {Promise<BucketRecords>} */
async function readBucket(client,key){
 const [kind,rawBucket]=key.split(':'),bucket=Number(rawBucket),entries=[],seen=new Set();
 let order=-1;
 // platformBucketRows pages at 500 records and yields between pages.
 for await(const row of platformBucketRows(client,kind,bucket)){
  const record=platformRecord(kind,[row.id,row.payload],row.store_order);
  requireValue(record.record_hash===row.record_hash,'Platform record checksum mismatch');
  requireValue(record.store_bucket===bucket,'Platform record bucket mismatch');
  requireValue(row.store_order>=order&&!seen.has(row.id),'Invalid platform record order or duplicate identity');
  seen.add(row.id);order=row.store_order;
  entries.push(Object.freeze([row.id,freezeJson(record.payload)]));
 }
 return Object.freeze(entries);
}

// Caller owns a REPEATABLE READ READ ONLY transaction spanning this operation.
// No pool, schema initialization, writer registration, or publication happens here.
// Publish the returned snapshot only after the caller successfully commits.
// An unchanged authority returns `previous` itself; no payloads are reread.
/**
 * @param {{query: (sql: string, params?: any[]) => Promise<any>}} client
 * @param {CommittedPlatformSnapshot} [previous]
 * @returns {Promise<CommittedPlatformSnapshot>}
 */
export async function loadCommittedPlatform(client,previous){
 const authority=await readPlatformAuthority(client);
 requireValue(validAuthority(authority),'Committed reader requires enforced SQL platform authority');
 const prior=usablePrevious(previous)?previous:undefined;
 if(prior&&samePlatformAuthority(prior.authority,authority))return prior;
 let changedKeys=await changedSince(client,prior,authority);
 const metadata=await readMetadata(client);
 const sameMetadata=prior&&platformHash(platformJson(prior.metadata))===metadata.hash;
 // The metadata row is cheap enough to verify on every new authority. A
 // disagreement with the audit invalidates its selective-refresh proof.
 if(changedKeys!==null&&!sameMetadata&&!changedKeys.includes('meta'))changedKeys=null;
 const full=changedKeys===null;
 const keys=full?allKeys:changedKeys;
 const collectionKeys=keys.filter(key=>key!=='meta');
 let buckets=prior?.buckets;
 if(full||collectionKeys.length){
  const prepared=new Map(full?[]:prior.buckets);
  for(const key of collectionKeys)prepared.set(key,await readBucket(client,key));
  buckets=immutableBuckets(prepared);
 }
 return Object.freeze({authority:Object.freeze({...authority}),buckets,
  metadata:sameMetadata?prior.metadata:metadata.value,changedKeys:Object.freeze([...keys])});
}
