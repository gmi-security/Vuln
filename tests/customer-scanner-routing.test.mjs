import assert from 'node:assert/strict';import test from 'node:test';
import {loadConnectorPreview,loadConnectorReview,loadScannerRouting,loadScannerTargets,loadConnectorStatus} from '../scripts/connector-preview-loader.mjs';
const build=await loadConnectorPreview(),review=await loadConnectorReview(),routing=await loadScannerRouting(),targets=await loadScannerTargets();
const env={NESSUS_URL:'https://fixture.invalid',NESSUS_ACCESS_KEY:'fixture',NESSUS_SECRET_KEY:'fixture'};
const metadata={companies:[{id:'A',name:'Alpha'},{id:'B',name:'Beta'}],defender:[],spotlight:[],connections:[],tiles:[]};
const preview=build(metadata,env),c=preview.candidates.find(c=>c.provider==='nessus'),hash=review.connectorDraftEvidence(c,preview.candidates).candidateHash;
const row={candidate_id:c.id,company_id:'A',provider:'nessus',source_scope:'17',candidate_hash:hash,binding_hash:hash,imported_hash:hash,
 binding_revision:1,current_binding_revision:1,revision:1,enabled:true,source_present:true,review_state:'reviewed',reviewed_at:'2026-10-10',
 proposal:{companyId:'A',tenantId:'17',authority:'findings-primary',targets:['10.0.0.0/24','host.example'],datasets:[]}};
test('scanner routing requires explicit Nessus opt-in and complete current folder/target approval',()=>{
 for(const v of ['',undefined,' '])assert.deepEqual(routing.reviewedScannerProviders(v),[]);
 assert.deepEqual(routing.reviewedScannerProviders('nessus'),['nessus']);
 for(const v of ['all','zap','nessus,','nessus,nessus'])assert.throws(()=>routing.reviewedScannerProviders(v));
 assert.equal(routing.scannerBindingScope('A',preview,row).sourceScope,'17');
 for(const edit of [{source_present:false},{review_state:'pending-review'},{imported_hash:'0'.repeat(64)},
  ...[{tenantId:'Alpha'},{tenantId:'017'},{tenantId:'0'},{targets:[]},{targets:['*.example.com']},{authority:'mirror'},{datasets:['data']}].map(p=>({proposal:{...row.proposal,...p}}))])
  assert.throws(()=>routing.scannerBindingScope('A',preview,{...row,...edit}));
 assert.throws(()=>routing.scannerBindingScope('A',build(metadata,{...env,NESSUS_URL:'https://changed.invalid'}),row));
});
test('target containment supports exact names and IPv4/IPv6 ranges without wildcards, suffix matching or DNS resolution',()=>{
 const match=targets.scannerTargetMatcher(['host.EXAMPLE.','10.0.0.0/24','2001:db8::/48','::ffff:192.0.2.1']);
 for(const v of ['HOST.example','10.0.0.1','10.0.0.128/25','2001:db8:0:1::9','2001:db8::/64','0:0:0:0:0:ffff:c000:201'])assert.equal(match(v),true,v);
 for(const v of ['other.host.example','host.example.evil','10.0.1.1','10.0.0.0/23','2001:db9::1','2001:db8::/32','192.0.2.1','host.example,evil','https://host.example'])assert.equal(match(v),false,v);
 for(const v of ['*.example','10.0.0.1-10.0.0.8','10.0.0.0/33','::/129','10.0.0.0/-1','::/064','010.0.0.1','host:443','fe80::1%eth0','host[10.0.0.1]'])assert.throws(()=>targets.scannerTargetMatcher([v]),v);
});
test('all scanned hosts including clean hosts must fit scope; findings must belong to that verified host set',()=>{
 const good={scannedHosts:[{hostname:'host.example',assetAliases:['host.example','10.0.0.1']}],findings:[{asset:'host.example',assetAliases:['10.0.0.1']}]};
 targets.assertScannerResultScope(['10.0.0.0/24'],good);
 assert.throws(()=>targets.assertScannerResultScope(['10.0.0.0/24'],{...good,scannedHosts:[...good.scannedHosts,{hostname:'foreign',assetAliases:['10.1.0.1']}]}),/outside/);
 assert.throws(()=>targets.assertScannerResultScope(['10.0.0.0/24'],{...good,findings:[{asset:'foreign',assetAliases:['10.0.0.1']}]}),/does not belong/);
 targets.assertScannerResultScope(['10.0.0.0/24'],{scannedHosts:[],findings:[]});
});

test('scanner approval status is customer-scoped and never exports private folder or target scope',async()=>{
 const project=await loadConnectorStatus(),draft={id:c.id,candidate:c,candidate_hash:hash,proposal:row.proposal,source_present:true,review_state:'reviewed',reviewed_at:row.reviewed_at};
 const status=routing.scannerRoutingStatus(row,preview,'nessus');
 const result=project('A',preview,[draft],true,undefined,[],[],[status]);assert.equal(result.items[0].review,'Scanner route approved');
 assert.doesNotMatch(JSON.stringify(result),/10.0.0|host.example|fixture.invalid|source_scope/);
 assert.equal(project('B',preview,[draft],true,undefined,[],[],[status]).items.length,0);
 assert.match(routing.scannerRoutingStatus({...row,current_binding_revision:2},preview,'nessus').review,/needs review/);
 assert.match(routing.scannerRoutingStatus(row,preview,'').routing,/switch is off/);
});

test('OSINT scanner scope requires explicit roots, an exact Artemis tag and fresh source evidence',()=>{
 const osintEnv={SPIDERFOOT_URL:'https://sf.fixture.invalid',ARTEMIS_API_URL:'https://ar.fixture.invalid',ARTEMIS_API_TOKEN:'fixture'};
 const p=build(metadata,osintEnv);
 assert.deepEqual(routing.reviewedScannerProviders('spiderfoot,artemis'),['spiderfoot','artemis']);
 for(const provider of ['spiderfoot','artemis']){
  const c=p.candidates.find(c=>c.provider===provider),hash=review.connectorDraftEvidence(c,p.candidates).candidateHash;
  const evidence={...row,candidate_id:c.id,candidate_hash:hash,imported_hash:hash,proposal:{...row.proposal,tenantId:provider==='artemis'?'ExactTag':null,targets:['acme.example','10.0.0.1']}};
  const scope=routing.scannerBindingScope('A',p,evidence);assert.equal(scope.provider,provider);
  assert.match(scope.sourceScope,provider==='artemis'?/^ExactTag$/:/^targets:[a-f0-9]{64}$/);
  for(const targets of [[],['*.example'],['10.0.0.0/24'],['EXAMPLE.','example']])assert.throws(()=>routing.scannerBindingScope('A',p,{...evidence,proposal:{...evidence.proposal,targets}}));
  assert.throws(()=>routing.scannerBindingScope('A',p,{...evidence,proposal:{...evidence.proposal,tenantId:provider==='artemis'?null:'FakeTenant'}}));
  if(provider==='spiderfoot')for(const key of ['SPIDERFOOT_TLS_INSECURE','SPIDERFOOT_USECASE'])assert.throws(()=>routing.scannerBindingScope('A',build(metadata,{...osintEnv,[key]:'changed'}),evidence));
 }
});
