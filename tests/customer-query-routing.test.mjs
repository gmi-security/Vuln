import assert from 'node:assert/strict';import test from 'node:test';
import {loadConnectorPreview,loadConnectorReview,loadQueryRouting,loadConnectorStatus} from '../scripts/connector-preview-loader.mjs';
const build=await loadConnectorPreview(),review=await loadConnectorReview(),routing=await loadQueryRouting();
const cid='a'.repeat(32),metadata={companies:[{id:'A',name:'Alpha'},{id:'B',name:'Beta'}],defender:[],spotlight:[],connections:[{source:'crowdstrike',revision:1}],tiles:[]};
const preview=build(metadata,{}),c=preview.candidates.find(c=>c.connectionRef==='dashboard:dashboard_source_connections:crowdstrike'),hash=review.connectorDraftEvidence(c,preview.candidates).candidateHash;
const row={candidate_id:c.id,company_id:'A',provider:'crowdstrike',source_scope:cid,candidate_hash:hash,binding_hash:hash,imported_hash:hash,
 binding_revision:1,current_binding_revision:1,revision:1,enabled:true,source_present:true,review_state:'reviewed',reviewed_at:'2026-10-10',
 proposal:{companyId:'A',tenantId:cid,authority:'query-only',targets:[],datasets:[]}};
test('saved-query approvals require the exact saved connection, CID and query-only authority',()=>{
 for(const v of ['',undefined,' '])assert.equal(routing.reviewedQueryRouting(v),false);
 assert.equal(routing.reviewedQueryRouting('crowdstrike'),true);
 for(const v of ['all','crowdstrike,','CrowdStrike'])assert.throws(()=>routing.reviewedQueryRouting(v));
 assert.equal(routing.queryBindingScope('A',preview,row).sourceScope,cid);
 for(const edit of [{source_present:false},{review_state:'pending-review'},{imported_hash:'0'.repeat(64)},
  ...[{tenantId:'Alpha'},{tenantId:null},{targets:['example.com']},{authority:'findings-primary'},{datasets:['vulnerabilities']}].map(p=>({proposal:{...row.proposal,...p}}))])
  assert.throws(()=>routing.queryBindingScope('A',preview,{...row,...edit}));
 assert.throws(()=>routing.queryBindingScope('B',preview,row));
 assert.throws(()=>routing.queryBindingScope('A',build({...metadata,connections:[{source:'crowdstrike',revision:2}]},{}),row));
});
test('query status distinguishes approval from activation and hides private scope from other customers',async()=>{
 const project=await loadConnectorStatus(),draft={id:c.id,candidate:c,candidate_hash:hash,proposal:row.proposal,source_present:true,review_state:'reviewed',reviewed_at:row.reviewed_at};
 const status=routing.queryRoutingStatus(row,preview,'crowdstrike');assert.equal(status.review,'Query route approved');
 const result=project('A',preview,[draft],true,undefined,[],[],[],[status]);assert.equal(result.items[0].review,'Query route approved');
 assert.deepEqual(result.items[0].data.domains,['saved-queries']);assert.match(result.items[0].data.lifecycle,/does not publish platform findings/);
 assert.doesNotMatch(JSON.stringify(result),new RegExp(cid+'|source_scope|connectionRevision'));
 assert.equal(project('B',preview,[draft],true,undefined,[],[],[],[status]).items.length,0);
 assert.match(routing.queryRoutingStatus({...row,current_binding_revision:2},preview,'crowdstrike').review,/needs review/);
 assert.match(routing.queryRoutingStatus(row,preview,'').routing,/switch is off/);
});
