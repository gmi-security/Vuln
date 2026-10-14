// Writes only disposable recovery targets. This does not select a publication,
// update source current_run, alter tickets or apply asset changes to the platform.
import {randomUUID,createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {privateShadowDatabase,projectDefenderFinding,insertDefenderShadowBatch,reconstructShadowSql} from './defender-platform-shadow.mjs';
const requireValue=(v,m)=>{if(!v)throw Error(m);};
export async function writeDefenderRefreshCandidate(target,candidate,{afterBatch,deadlineMs=300000}={}){
  await privateShadowDatabase(target,'target');
  requireValue(Number.isInteger(deadlineMs)&&deadlineMs>0&&deadlineMs<=300000,'Invalid candidate deadline');
  const {companyId,sourceRun,baselineSavedAt,records,assets,...provenance}=candidate;
  requireValue(/^CO-[A-Za-z0-9-]+$/.test(companyId)&&typeof sourceRun==='string'&&sourceRun&&Number.isFinite(Date.parse(baselineSavedAt)),'Invalid candidate scope');
  requireValue(Array.isArray(records)&&records.length<=500000&&Array.isArray(assets)&&assets.length<=100000&&assets.every(a=>a.companyId===companyId),'Invalid candidate records or assets');
  const projectionId=randomUUID(),started=Date.now(),digest=createHash('sha256');let created=false,batches=0;
  const check=()=>requireValue(Date.now()-started<deadlineMs,'Candidate build deadline exceeded');
  await target.query("SET statement_timeout='15s';SET lock_timeout='2s'");
  try{
    await target.query(`INSERT INTO defender_shadow_generations(company_id,projection_id,model_version,source_run,snapshot_saved_at,state) VALUES($1,$2,2,$3,$4,'building')`,[companyId,projectionId,sourceRun,baselineSavedAt]);created=true;
    for(let offset=0;offset<records.length;offset+=500){
      check();
      // Legacy snapshot persistence drops optional undefined fields too. Verify
      // the exact persisted representation, not an in-memory undefined property.
      const originals=JSON.parse(JSON.stringify(records.slice(offset,offset+500))),projected=originals.map((f,i)=>({...projectDefenderFinding(f,companyId),legacyOrder:offset+i}));
      const serialized=JSON.stringify(projected);requireValue(Buffer.byteLength(serialized)<=16*1024*1024,'Candidate batch exceeds byte limit');digest.update(serialized);
      await target.query('BEGIN');
      try{
        await target.query(insertDefenderShadowBatch,[companyId,projectionId,serialized]);
        if(!batches)for(const table of ['findings','workflow','assessments','evidence'])await target.query(`ANALYZE defender_shadow_${table} (company_id,projection_id,finding_id)`);
        const {rows}=await target.query(`${reconstructShadowSql} AND f.finding_id=ANY($3::text[])`,[companyId,projectionId,originals.map(f=>f.id)]);
        const expected=new Map(originals.map(f=>[f.id,f]));
        requireValue(rows.length===originals.length&&rows.every(r=>isDeepStrictEqual(r.record,expected.get(r.id))),'Candidate reconstruction differs');
        await target.query('COMMIT');
      }catch(error){await target.query('ROLLBACK');throw error;}
      batches++;await afterBatch?.({batches,count:offset+originals.length,projectionId});
    }
    for(const [table,columns] of [['findings','company_id,projection_id,finding_id,issue_key,asset_key'],
      ['workflow','company_id,projection_id,finding_id,status'],['assessments','company_id,projection_id,finding_id,severity'],
      ['evidence','company_id,projection_id,finding_id,source_run,active']]){
      check();await target.query(`ANALYZE defender_shadow_${table} (${columns})`);
    }
    check();const evidence=JSON.stringify({...provenance,assets,recordDigest:digest.digest('hex')});
    requireValue(Buffer.byteLength(evidence)<=32*1024*1024,'Candidate provenance exceeds byte limit');
    await target.query('BEGIN');
    try{
      await target.query(`INSERT INTO defender_shadow_refresh_candidates(company_id,projection_id,baseline_run,source_revision,evidence) VALUES($1,$2,$3,$4,$5::jsonb)`,[companyId,projectionId,candidate.baselineRun,candidate.sourceRevision,evidence]);
      await target.query(`UPDATE defender_shadow_generations SET state='verified',finding_count=$3,verified_at=now() WHERE company_id=$1 AND projection_id=$2 AND state='building'`,[companyId,projectionId,records.length]);
      await target.query('COMMIT');
    }catch(error){await target.query('ROLLBACK');throw error;}
    return {companyId,projectionId,sourceRun,count:records.length,batches,elapsedMs:Date.now()-started};
  }catch(error){
    if(created)await target.query(`UPDATE defender_shadow_generations SET state='failed',verified_at=NULL WHERE company_id=$1 AND projection_id=$2 AND state='building'`,[companyId,projectionId]).catch(()=>{});
    throw error;
  }
}
