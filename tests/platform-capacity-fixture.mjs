// Synthetic review rows in the already guarded disposable database ONLY.
// This measures worker capacity for every retained customer. It is not live
// connector/tenant acceptance and must never be used as an approval importer.
import assert from 'node:assert/strict';
import {reportingDigest} from '../lib/db/customer-reporting-revisions.mjs';
export async function prepareCapacityFixture(db){
 const guard=(await db.query("SELECT current_database() db,current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.match(guard.db,/^vuln2_reporting_test_[a-f0-9]+$/);assert.ok(guard.dir.startsWith('/home/codex/vuln-recovery/')&&!guard.listen);
 const companies=(await db.query("SELECT id FROM app_companies WHERE payload->'isDemo' IS DISTINCT FROM 'true'::jsonb ORDER BY id")).rows.map(r=>r.id);
 const roles=(await db.query(`SELECT DISTINCT company_id,connector provider,'findings-primary' authority FROM app_findings
  UNION SELECT DISTINCT company_id,connector,'findings-primary' FROM app_scans
  UNION SELECT DISTINCT company_id,source,'inventory' FROM app_assets WHERE source NOT IN ('manual','inferred')
  UNION SELECT DISTINCT company_id,s,'findings-primary' FROM app_findings,LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(payload->'seenBy')='array' THEN payload->'seenBy' ELSE '[]'::jsonb END) s
  UNION SELECT DISTINCT company_id,e->>'source','enrichment' FROM app_findings,LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(payload->'enrichments')='array' THEN payload->'enrichments' ELSE '[]'::jsonb END) e`)).rows;
 const imported=(await db.query("INSERT INTO connector_registry_imports(fingerprint,actor,candidate_count) VALUES($1,'private-capacity-fixture',0) RETURNING id",[reportingDigest('private-capacity')])).rows[0].id;
 for(const companyId of companies){
  if((await db.query('SELECT 1 FROM customer_source_selections WHERE company_id=$1',[companyId])).rowCount)continue;
  const selected=new Map();
  for(const row of roles.filter(r=>r.company_id===companyId)){
   assert.ok(typeof row.provider==='string'&&/^[a-z]+$/.test(row.provider));
   if(!selected.has(row.provider)||row.authority==='findings-primary')selected.set(row.provider,row.authority);
  }
  const own=[];
  for(const [provider,authority] of selected){
   const id=reportingDigest(['private-capacity',companyId,provider]),candidate={provider,fixture:true},hash=reportingDigest(candidate),proposal={companyId,authority};
   await db.query("INSERT INTO customer_connector_drafts(id,candidate,candidate_hash,proposal,last_seen_import,review_state,reviewed_by,reviewed_at) VALUES($1,$2,$3,$4,$5,'reviewed','private-capacity-fixture',now())",[id,JSON.stringify(candidate),hash,JSON.stringify(proposal),imported]);
   await db.query("INSERT INTO customer_connector_bindings(candidate_id,company_id,candidate_hash,proposal,revision,review_state,reviewed_by,reviewed_at) VALUES($1,$2,$3,$4,1,'reviewed','private-capacity-fixture',now())",[id,companyId,hash,JSON.stringify(proposal)]);
   own.push([id,1,hash,hash,true,'reviewed',proposal]);
  }
  own.sort((a,b)=>a[0].localeCompare(b[0]));
  await db.query("INSERT INTO customer_source_selections(company_id,revision,state,bindings_fingerprint,mirrors,sources,reviewed_by) VALUES($1,1,'reviewed',$2,'[]','[]','private-capacity-fixture')",[companyId,reportingDigest(own)]);
 }
 return companies;
}
