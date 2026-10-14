// Every caller owns its transaction. No schema creation, pools, credentials or
// process-global authority cache: a mode change is observed in the same MVCC
// snapshot as the data that it selects.
export async function readPlatformAuthority(client, {lock=false}={}) {
 const present=(await client.query("SELECT to_regclass('public.app_store_authority')::text relation")).rows[0]?.relation;
 if(!present)return null;
 const row=(await client.query(`SELECT mode,enforced,epoch::text,revision::text FROM public.app_store_authority WHERE id=1${lock?' FOR UPDATE':''}`)).rows[0];
 if(!row||!['legacy','sql'].includes(row.mode)||!/^\d+$/.test(row.epoch)||!/^\d+$/.test(row.revision))throw Error('Invalid platform authority');
 return row;
}
export function samePlatformAuthority(a,b) {
 return a?.mode===b?.mode&&a?.epoch===b?.epoch&&a?.revision===b?.revision&&a?.enforced===b?.enforced;
}
export async function bindPlatformWriter(client,expected,operation='save') {
 const actual=await readPlatformAuthority(client,{lock:true});
 if(!samePlatformAuthority(actual,expected))throw Object.assign(Error('Platform authority changed; reload before writing'),{code:'platform-writer-stale'});
 if(!actual)return null;
 if(!['save','backfill','reverse'].includes(operation))throw Error('Invalid platform operation');
 await client.query("SELECT set_config('vuln2.store_epoch',$1,true),set_config('vuln2.store_revision',$2,true),set_config('vuln2.store_operation',$3,true)",[actual.epoch,actual.revision,operation]);
 return actual;
}
export async function platformMetadata(client,authority) {
 const current=authority===undefined?await readPlatformAuthority(client):authority;
 const row=current?.mode==='sql'?
  (await client.query('SELECT payload data FROM public.app_store_metadata WHERE id=1')).rows[0]:
  (await client.query("SELECT data FROM public.vuln_store WHERE key='meta'")).rows[0];
 if(!row?.data||typeof row.data!=='object'||Array.isArray(row.data))throw Error('Missing platform metadata');
 return row.data;
}
