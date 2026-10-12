import test from 'node:test';
import assert from 'node:assert/strict';
import {createComparison,createPlatformTotals} from '../scripts/source-platform-comparison.mjs';
const source=[{device:'d',cve:'CVE-2026-1234',instances:3,severity:'HIGH',cvss:8}];
const finding={device:'d',cve:'CVE-2026-1234',severity:'High',cvss:8,status:'Open',active:true,run:'r',connector:'defender',seenBy:['defender']};
test('groups source instances and permits preserved accepted workflow',()=>{
  const c=createComparison(source,new Map(),'r','r');c.add({...finding,status:'Risk Accepted'});
  const r=c.finish();assert.equal(r.sourceInstances,3);assert.equal(r.matchedPairs,1);assert.equal(r.currentSourceProjectionMatches,true);
  assert.equal(r.matchedStatuses['Risk Accepted'],1);
});
test('missing, duplicated, inactive and stale generation evidence is not parity',()=>{
  const c=createComparison([...source,{...source[0],device:'missing'}],new Map(),'r','old');
  c.add({...finding,active:false,run:'old'});c.add(finding);const r=c.finish();
  assert.equal(r.missingPairs,1);assert.equal(r.duplicatePlatformPairs,1);assert.equal(r.matchedInactive,1);
  assert.equal(r.matchedOlderGeneration,1);assert.equal(r.currentSourceProjectionMatches,false);
});
test('retained findings distinguish missing devices and heartbeat closure evidence',()=>{
  const c=createComparison([],new Map([['d','2026-10-08'],['fresh','2026-10-10']]),'r','r');
  for(const device of ['d','fresh','absent'])c.add({...finding,device,observed:'2026-10-09'});
  const r=c.finish();
  assert.deepEqual(r.absentClosureEvidence,{'heartbeat-before-observation':1,'heartbeat-at-or-after-observation':1,'device-absent':1});
  assert.deepEqual(r.absentOpenClosureEvidence,r.absentClosureEvidence);assert.equal(r.absentOpenActive,3);
});
test('assessment difference retains corroborating-source classification',()=>{
  const c=createComparison(source,new Map(),'r','r');c.add({...finding,severity:'Critical',cvss:9.8,seenBy:['defender','nessus']});
  const r=c.finish();assert.equal(r.severityDifferences,1);assert.equal(r.scoreDifferences,1);assert.equal(r.assessmentDifferencesWithOtherSources,1);
});
test('platform totals separate workflow, web, exposure and endpoint CVEs',()=>{
  const t=createPlatformTotals();for(const row of [finding,{...finding,status:'Risk Accepted'},
    {...finding,connector:'burp',cve:'WEB-1'},{...finding,connector:'spiderfoot'}])t.add(row);
  const r=t.finish();assert.equal(r.openRemediation,2);assert.equal(r.openEndpoint,1);assert.equal(r.openWeb,1);assert.equal(r.openExposure,1);assert.equal(r.uniqueOpenEndpointCves,1);
});
