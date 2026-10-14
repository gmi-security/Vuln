import assert from 'node:assert/strict';
import test from 'node:test';
import {loadSpotlightSummaryModules} from '../scripts/source-read-model-loader.mjs';
const {createSpotlightSummaryAccumulator:create,validateSpotlightSummary:validate,matchesSpotlightTenant,summaryLimits}=await loadSpotlightSummaryModules();
const row=(extra={})=>({source_id:'1',id:'1',company_id:'A',cve:'CVE-2026-1000',status:'open',cid:'tenant',aid:'host',raw_cve:'CVE-2026-1000',raw_status:'open',raw_severity:'HIGH',score:7.5,suppressed:false,...extra});
test('completed summaries include recommended fixes without any ticket drafts',()=>{
  const patch={id:'1',cid:'tenant',aid:'host',status:'open',cve:{id:'CVE-2026-1000',severity:'HIGH',base_score:7.5},
    apps:[{remediation_info:{recommended_id:'recommended',minimum_id:'minimum'}}],remediation:{entities:[
      {id:'recommended',title:'Recommended update',action:'Install version 3',recommendation_type:'recommended'},
      {id:'minimum',title:'Minimum update',action:'Install version 2',recommendation_type:'minimum'}]}};
  const a=create('A');a.add(row({patch}));a.add(row({source_id:'2',id:'2',aid:'host2',patch:{...patch,id:'2',aid:'host2'}}));
  a.add(row({source_id:'3',id:'3',suppressed:true,patch:{...patch,id:'3'}}));
  const result=a.finish().topFixes;
  assert.ok(result,'a saved top-fix summary is required');
  assert.equal(result.totalFixes,1);assert.equal(result.affectedDevices,2);assert.equal(result.findingCount,2);
  assert.equal(result.rows[0].remediation,'Install version 3');assert.equal(result.rows[0].deviceCount,2);
});
test('deduplicates device/CVE pairs but retains source instances, nullable scores and highest CVE severity',()=>{
  const a=create('A');a.add(row());a.add(row({source_id:'2',id:'2',raw_severity:'CRITICAL',score:null}));
  a.add(row({source_id:'3',id:'3',cid:'other',raw_severity:'LOW',score:1}));
  const r=a.finish();assert.equal(r.summary.sourceInstances,3);assert.equal(r.summary.deviceCveFindings,2);assert.equal(r.summary.affectedDevices,2);
  assert.equal(r.rows[0].severity,'CRITICAL');assert.equal(r.rows[0].cvss,7.5);assert.equal(r.summary.severity.sourceInstances.HIGH,1);
  assert.equal(r.summary.severity.uniqueCves.CRITICAL,1);
  validate(r.summary,[{severity:'CRITICAL',cves:1,devices:2,findings:3}]);
});
test('exclusion order and unknown suppression are explicit; closed and non-CVE rows need no invented device',()=>{
  const a=create('A');a.add(row({status:'closed',aid:null}));a.add(row({cve:'CS-abc',aid:null}));
  a.add(row({suppressed:true,aid:null}));a.add(row({suppressed:'true',raw_severity:'odd',score:'bad'}));
  const r=a.finish();assert.equal(r.scanned,4);assert.equal(r.summary.sourceInstances,1);assert.equal(r.summary.unknownSuppressionInstances,1);
  assert.equal(r.summary.excludedSuppressedInstances,1);assert.equal(r.summary.excludedNonCveInstances,1);assert.equal(r.rows[0].cvss,null);
  assert.equal(r.rows[0].severity,'UNKNOWN');
});
test('incomplete or conflicting eligible records and customer mixing fail instead of being dropped',()=>{
  for(const bad of [{company_id:'B'},{aid:''},{cid:null},{id:'different'},{raw_cve:'CVE-2026-9999'},{raw_status:'closed'}])assert.throws(()=>create('A').add(row(bad)));
});
test('resource caps fail explicitly before publishing; cannot silently truncate',()=>{
  for(const limits of [{records:0},{pairs:summaryLimits.pairs+1}])assert.throws(()=>create('A',{...summaryLimits,...limits}));
  for(const key of ['records','pairs','devices','cves']){
    const a=create('A',{...summaryLimits,[key]:1});a.add(row());
    assert.throws(()=>a.add(row({source_id:'2',id:'2',cve:'CVE-2026-2000',raw_cve:'CVE-2026-2000',aid:'other'})),/limit/);
  }
});
test('empty generation has real zero totals; stored aggregate corruption is rejected',()=>{
  const empty=create('A').finish();validate(empty.summary,[]);assert.equal(empty.summary.uniqueCves,0);
  const a=create('A');a.add(row());const r=a.finish();
  assert.throws(()=>validate(r.summary,[]));assert.throws(()=>validate({...r.summary,affectedDevices:0},[{severity:'HIGH',cves:1,devices:1,findings:1}]));
});
test('CVE ordering is severity, affected devices, then deterministic CVE; source score zero is retained',()=>{
  const a=create('A');a.add(row({cve:'CVE-2026-2000',raw_cve:'CVE-2026-2000',score:0}));a.add(row());
  assert.deepEqual(a.finish().rows.map(v=>v.cve),['CVE-2026-1000','CVE-2026-2000']);assert.equal(a.finish().rows[1].cvss,0);
});

test('vendor provenance covers closed and suppressed records, rejects mixed/missing tenants and cannot prove an empty run',()=>{
  const cid='a'.repeat(32),a=create('A');a.add(row({cid}));
  assert.ok(matchesSpotlightTenant(a.finish().vendorScope,cid,1));
  assert.equal(matchesSpotlightTenant(a.finish().vendorScope,'b'.repeat(32),1),false);
  assert.equal(matchesSpotlightTenant(a.finish().vendorScope,cid,2),false);
  a.add(row({source_id:'2',id:'2',cid:'b'.repeat(32),status:'closed'}));
  assert.equal(matchesSpotlightTenant(a.finish().vendorScope,cid,2),false);
  const b=create('A');b.add(row({cid}));b.add(row({source_id:'2',id:'2',cid:null,suppressed:true}));
  assert.equal(b.finish().vendorScope.missingRows,1);assert.equal(matchesSpotlightTenant(b.finish().vendorScope,cid,2),false);
  assert.equal(matchesSpotlightTenant(create('A').finish().vendorScope,cid,0),false);
});

const placeholder=(extra={})=>row({source_id:'gone',id:'gone',cve:'CS-gone',status:'closed',cid:null,aid:null,
  raw_cve:null,raw_status:null,raw_severity:null,score:null,suppressed:null,local_placeholder:true,...extra});
test('exact local placeholders are accounted for without inventing tenant evidence or changing findings',()=>{
  const cid='a'.repeat(32),a=create('A');a.add(row({cid}));const before=a.finish();a.add(placeholder());const after=a.finish();
  assert.deepEqual(after.summary,before.summary);assert.deepEqual(after.rows,before.rows);
  assert.equal(after.scanned,2);assert.equal(after.vendorScope.localPlaceholderRows,1);assert.equal(after.vendorScope.missingRows,0);
  assert.ok(matchesSpotlightTenant(after.vendorScope,cid,2));
  const only=create('A');only.add(placeholder());assert.equal(matchesSpotlightTenant(only.finish().vendorScope,cid,1),false);
  const unproven=create('A');unproven.add(row({cid}));unproven.add(placeholder({local_placeholder:false}));
  assert.equal(unproven.finish().vendorScope.missingRows,1);assert.equal(matchesSpotlightTenant(unproven.finish().vendorScope,cid,2),false);
  for(const bad of [{id:'wrong'},{status:'open'},{cve:'CVE-2026-1000'},{cid},{aid:'host'},{raw_status:'closed'},
    {raw_cve:'CS-gone'},{suppressed:false}])assert.throws(()=>create('A').add(placeholder(bad)),/placeholder/);
  for(const bad of [{version:1},{localPlaceholderRows:-1},{localPlaceholderRows:2},{localPlaceholderRows:0.5},{rows:2.5}])
    assert.equal(matchesSpotlightTenant({...after.vendorScope,...bad},cid,2),false);
});
