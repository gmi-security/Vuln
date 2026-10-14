import {reportingDigest} from './customer-reporting-revisions.mjs';
const requireValue=(ok)=>{if(!ok)throw Object.assign(Error('Customer reporting source review is required'),{code:'report-review-required'});};

// Stored approval pin; the web service also verifies current connection metadata
// against buildConnectorPreview before returning any saved report. This pin
// makes a concurrent review/binding change invalidate the worker's output.
export async function readReportingSourceReview(client,companyId){
 const {rows:[saved]}=await client.query('SELECT * FROM public.customer_source_selections WHERE company_id=$1',[companyId]);
 requireValue(saved?.state==='reviewed'&&saved.reviewed_at&&saved.bindings_fingerprint);
 const {rows}=await client.query(`SELECT b.candidate_id AS id,b.revision,b.candidate_hash AS "candidateHash",d.candidate_hash AS "importedHash",
  d.source_present AS "sourcePresent",b.review_state AS "reviewState",b.reviewed_at AS "reviewedAt",b.proposal,d.candidate->>'provider' AS provider
  FROM public.customer_connector_bindings b JOIN public.customer_connector_drafts d ON d.id=b.candidate_id
  WHERE b.company_id=$1 ORDER BY b.candidate_id LIMIT 1001`,[companyId]);
 requireValue(rows.length<=1000&&rows.every(r=>r.proposal?.companyId===companyId));
 const own=rows.filter(r=>r.reviewState!=='dismissed').sort((a,b)=>a.id.localeCompare(b.id));
 requireValue(own.every(r=>r.sourcePresent&&r.reviewState==='reviewed'&&r.reviewedAt&&r.candidateHash===r.importedHash));
 const fingerprint=reportingDigest(own.map(r=>[r.id,r.revision,r.candidateHash,r.importedHash,r.sourcePresent,r.reviewState,r.proposal]));
 requireValue(fingerprint===saved.bindings_fingerprint);
 const allowed={findings:new Set(),scans:new Set(),assets:new Set(['manual','inferred']),enrichment:new Set()};
 for(const row of own){
  const role=row.proposal.authority;
  if(role==='findings-primary')for(const key of ['findings','scans','assets'])allowed[key].add(row.provider);
  if(role==='inventory'){allowed.assets.add(row.provider);if(row.provider==='nmap')allowed.scans.add(row.provider);}
  if(role==='enrichment')allowed.enrichment.add(row.provider);
 }
 return {revision:saved.revision,pin:reportingDigest({companyId,selection:saved,bindings:own}),allowed};
}
export function checkReportingRecordSources(review,kind,record){
 const allowed=review.allowed;
 if(kind==='findings'){
  requireValue(allowed.findings.has(record.connector));
  requireValue((record.seenBy??[]).every(source=>allowed.findings.has(source)));
  requireValue((record.enrichments??[]).every(e=>allowed.enrichment.has(e.source)));
 }else if(kind==='scans')requireValue(allowed.scans.has(record.connector));
 else requireValue(allowed.assets.has(record.source));
}
