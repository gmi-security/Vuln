import {createHash} from 'node:crypto';
// v2 hashes each Map entry independently, retaining only IDs and digests.
// Bucket and Map order do not affect the result; nested array order does.
export const reverseDigestVersion=2;
export const reverseMapKeys=new Set(['findings','assets','scans','companies','folders','compensatingControls','identityAliases']);
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
export const reverseValueDigest=v=>createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
export function createReverseDigest(){
  const fields=new Map();
  return {
    startMap(key){if(fields.has(key))throw Error('Duplicate snapshot field');fields.set(key,new Map());},
    addEntryHash(key,id,digest){const rows=fields.get(key);
      if(!(rows instanceof Map)||typeof id!=='string'||rows.has(id))throw Error('Invalid snapshot Map identity');rows.set(id,digest);},
    addValue(key,value){if(fields.has(key))throw Error('Duplicate snapshot field');fields.set(key,reverseValueDigest(value));},
    finish(){const hash=createHash('sha256'),add=v=>hash.update(JSON.stringify(v)+'\n');add({version:reverseDigestVersion});
      for(const key of [...fields.keys()].sort()){
        const value=fields.get(key);add(key);
        if(value instanceof Map){add({kind:'map',count:value.size});for(const id of [...value.keys()].sort())add([id,value.get(id)]);}
        else add({kind:'value',digest:value});
      }return hash.digest('hex');}
  };
}
export function reverseSnapshotDigest(snapshot){
  if(!snapshot||typeof snapshot!=='object'||Array.isArray(snapshot))throw Error('Complete snapshot required');
  const digest=createReverseDigest();
  for(const [key,value] of Object.entries(snapshot)){
    if(reverseMapKeys.has(key)){
      if(!Array.isArray(value))throw Error('Snapshot Map required');digest.startMap(key);
      for(const row of value){if(!Array.isArray(row)||row.length!==2)throw Error('Invalid snapshot Map identity');digest.addEntryHash(key,row[0],reverseValueDigest(row));}
    }else digest.addValue(key,value);
  }return digest.finish();
}
