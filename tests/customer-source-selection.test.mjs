import assert from 'node:assert/strict';
import test from 'node:test';
import {loadConnectorPreview,loadConnectorReview,loadSourceSelection} from '../scripts/connector-preview-loader.mjs';
import {parseRegistryArgs,registryFailure} from '../scripts/customer-connector-registry.mjs';
const build=await loadConnectorPreview(),review=await loadConnectorReview(),api=await loadSourceSelection();
const env={FALCON_CLIENT_ID:'fixture',FALCON_CLIENT_SECRET:'fixture',FALCON_CUSTOMER:'Alpha'};
const metadata={companies:[{id:'A',name:'Alpha'},{id:'B',name:'Beta'}],defender:[{companyId:'A',tenantId:'private-tenant',revision:1}],spotlight:[],connections:[{source:'elastic',revision:1}],tiles:[]};
const preview=build(metadata,env);
function row(provider,scope={},p=preview){
 const candidate=p.candidates.find(c=>c.provider===provider),h=review.connectorDraftEvidence(candidate,p.candidates).candidateHash;
 return {id:candidate.id,provider,revision:1,candidateHash:h,importedHash:h,sourcePresent:true,reviewState:'reviewed',reviewedAt:'2026-10-10',
  proposal:{companyId:'A',tenantId:candidate.tenantId??(provider==='crowdstrike'?'a'.repeat(32):null),authority:provider==='elastic'?'mirror':'findings-primary',datasets:provider==='elastic'?['private-dataset']:[],targets:[],...scope}};
}
const cs=row('crowdstrike'),es=row('elastic'),defender=row('defender'),link={candidateId:es.id,primaryId:cs.id,evidenceRef:'CHANGE-42 source mapping'};
const current=(rows=[cs,es],links=[link])=>api.buildReviewedSourceSelection('A',preview,rows,links);
const saved=(rows=[cs,es],links=[link])=>({company_id:'A',revision:1,state:'reviewed',bindings_fingerprint:current(rows,links).fingerprint,mirrors:links,sources:current(rows,links).entries,reviewed_at:'2026-10-10',reviewed_by:'operator:fixture'});

test('approved CS plus explicitly reviewed Elastic mirror selects one primary without combined totals or activation',()=>{
 const result=current();assert.equal(result.plan.state,'ready-for-comparison');
 assert.deepEqual(result.plan.proposedSources,[cs.id]);assert.deepEqual(result.plan.excludedMirrors,[es.id]);
 assert.equal(result.plan.combinedPlatformFindings,null);assert.equal(result.plan.canActivate,false);
 const status=api.sourceSelectionStatus('A',preview,[cs,es],saved());
 assert.equal(status.state,'reviewed');assert.equal(status.primaryCount,1);assert.equal(status.mirrorCount,1);
 assert.doesNotMatch(JSON.stringify(status),/private-|CHANGE-42|operator:|aaaaaaa/);
});
test('independent Defender and CrowdStrike are retained but require record correlation',()=>{
 const result=current([cs,defender],[]);assert.equal(result.plan.state,'requires-record-correlation');assert.equal(result.plan.combinedPlatformFindings,null);
 assert.equal(api.sourceSelectionStatus('A',preview,[cs,defender],saved([cs,defender],[])).primaryCount,2);
});
test('every mirror has a same-customer primary; missing, cyclic, duplicate and unsupported links fail',()=>{
 for(const links of [[],[link,link],[{...link,primaryId:es.id}],[{...link,primaryId:'0'.repeat(64)}],[{...link,evidenceRef:''}]])assert.throws(()=>current([cs,es],links));
 assert.throws(()=>current([{...cs,proposal:{...cs.proposal,companyId:'B'}},es]),/binding set/);
 assert.throws(()=>current([es],[{...link,primaryId:es.id}]),/Mirror target/);
 assert.throws(()=>current([cs,{...es,proposal:{...es.proposal,datasets:['logs-*']}}]),/exact Elasticsearch/);
});
test('unreviewed, revoked, missing and changed configuration cannot silently produce current selection',()=>{
 for(const patch of [{reviewState:'pending-review'},{sourcePresent:false},{reviewedAt:null},{candidateHash:'0'.repeat(64)},{importedHash:'0'.repeat(64)}]){
  assert.throws(()=>current([{...cs,...patch},es]),/Review all/);
  assert.equal(api.sourceSelectionStatus('A',preview,[{...cs,...patch},es],saved()).state,'needs-review');
 }
 const changed=build({...metadata,connections:[{source:'elastic',revision:2}]},env);
 assert.equal(api.sourceSelectionStatus('A',changed,[cs,es],saved()).state,'needs-review');
 assert.equal(api.sourceSelectionStatus('A',preview,[cs,es],{...saved(),state:'revoked'}).state,'revoked');
 assert.equal(api.sourceSelectionStatus('A',preview,[cs,es]).state,'unreviewed');
});
test('new or removed bindings, revision changes and altered saved primary evidence invalidate the whole selection',()=>{
 for(const rows of [[cs,es,defender],[cs],[{...cs,revision:2},es],[cs,{...es,reviewState:'dismissed'}]])
  assert.equal(api.sourceSelectionStatus('A',preview,rows,saved()).state,'needs-review');
 assert.equal(api.sourceSelectionStatus('A',preview,[cs,es],{...saved(),sources:[]}).state,'needs-review');
 assert.throws(()=>api.sourceSelectionStatus('B',preview,[],saved()),/different customer/);
});
test('scoped reader limitations and separate data roles are retained without invented endpoint counts',()=>{
 const result=current([{...defender,proposal:{...defender.proposal,targets:['host.example']}}],[]);
 assert.equal(result.plan.state,'needs-review');assert.ok(result.plan.issues.some(i=>i.code==='saved-reader-unavailable'));
 const inventory=row('defender',{authority:'inventory'});
 assert.equal(current([inventory],[]).plan.state,'no-findings-source');
});
test('two configured primaries for the same vendor tenant are rejected including CID case variants',()=>{
 const p=build({...metadata,defender:[]},{...env,FALCON_CLIENT_ID_2:'fixture2',FALCON_CLIENT_SECRET_2:'fixture2',FALCON_CUSTOMER_2:'Alpha'});
 const sources=p.candidates.filter(c=>c.provider==='crowdstrike');assert.equal(sources.length,2);
 const rows=sources.map((c,i)=>{const h=review.connectorDraftEvidence(c,p.candidates).candidateHash;return {...cs,id:c.id,candidateHash:h,importedHash:h,proposal:{...cs.proposal,tenantId:i?'A'.repeat(32):'a'.repeat(32)}};});
 assert.throws(()=>api.buildReviewedSourceSelection('A',p,rows,[]),/Duplicate primary/);
});
test('operator format rejects guessed fields, credentials, duplicate mirrors and malformed revisions',()=>{
 const value={companyId:'A',expectedRevision:0,decision:'reviewed',bindingsFingerprint:current().fingerprint,mirrors:[link],note:'Verified source mapping'};
 assert.equal(api.sourceSelectionReview(value).mirrors.length,1);
 for(const changes of [{actor:'claimed'},{apiKey:'PRIVATE'},{expectedRevision:-1},{bindingsFingerprint:null},{decision:'activate'},{mirrors:[link,link]}])assert.throws(()=>api.sourceSelectionReview({...value,...changes}));
 assert.equal(api.sourceSelectionReview({...value,decision:'revoked',bindingsFingerprint:null,mirrors:[]}).decision,'revoked');
 assert.equal(parseRegistryArgs(['review-sources','--input','private.json']).command,'review-sources');
 assert.equal(parseRegistryArgs(['export-sources','--company','A','--output','private.json']).command,'export-sources');
 assert.throws(()=>parseRegistryArgs(['review-sources']));assert.doesNotMatch(registryFailure(Error('PRIVATE_CONNECTION')),/PRIVATE_CONNECTION/);
});
test('missing review schema is a read-only explicit status, never a migration',async()=>{
 const calls=[],client={query:async sql=>{calls.push(sql);return{rows:[{selection:null}]};}};
 assert.equal((await api.readSourceSelectionStatus(client,'A',preview)).state,'not-installed');
 assert.equal(calls.length,1);assert.ok(calls.every(s=>s.startsWith('SELECT')));
});

test('JSONB object-key reordering preserves review but substantive changes do not',()=>{
 const reverse=value=>Array.isArray(value)?value.map(reverse):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).reverse().map(([k,v])=>[k,reverse(v)])):value;
 assert.equal(api.sourceSelectionStatus('A',preview,reverse([cs,es]),reverse(saved())).state,'reviewed');
 const changed=reverse(saved());changed.sources[0].provider='other';
 assert.equal(api.sourceSelectionStatus('A',preview,[cs,es],changed).state,'needs-review');
});

test('declaring an Elastic query dataset mirror preserves its existing query-only binding role',()=>{
 const query={...es,proposal:{...es.proposal,authority:'query-only'}};
 const selected=current([cs,query],[link]);assert.deepEqual(selected.plan.excludedMirrors,[es.id]);
 assert.equal(query.proposal.authority,'query-only');assert.deepEqual(current([cs,query],[]).plan.excludedMirrors,[]);
});
