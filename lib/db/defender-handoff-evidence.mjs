import {createHash} from 'node:crypto';
// Stable across JSONB key order and snapshot bucket order. Hash records one at
// a time rather than creating another whole-customer JSON string.
function canonical(value){
  if(Array.isArray(value))return value.map(canonical);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
  return value;
}
export function handoffBaselineDigest({company,runId,findings,assets,controls}){
  const hash=createHash('sha256'),add=value=>hash.update(JSON.stringify(canonical(JSON.parse(JSON.stringify(value))))+'\n');
  add({version:1,company,runId:runId??null});
  for(const [kind,rows] of [['findings',findings],['assets',assets],['controls',controls]]){
    add({kind,count:rows.length});
    for(const row of [...rows].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0))add(row);
  }
  return hash.digest('hex');
}
