import test from 'node:test';
import assert from 'node:assert/strict';
import {shadowReadRequest,shadowCursor,readDefenderShadow,validShadowSummary} from '../lib/db/defender-shadow-reads.mjs';
const request={companyId:'CO-A',projectionId:'11111111-1111-4111-8111-111111111111',view:'findings',status:'open'};
test('cursor binds customer, projection, view and workflow filter',()=>{
  const cursor=shadowCursor(request,100);
  assert.equal(shadowReadRequest({...request,cursor}).after,100);
  for(const extra of [{companyId:'CO-B'},{projectionId:'22222222-2222-4222-8222-222222222222'},{view:'cves'},{status:'Resolved'}])
    assert.throws(()=>shadowReadRequest({...request,...extra,cursor}));
});
test('invalid scope, cursor and unbounded pages fail before any database request',async()=>{
  let calls=0;const client={query(){calls++;throw new Error('Unexpected database call');}};
  for(const extra of [{companyId:''},{limit:0},{limit:101},{limit:1.5},{cursor:'{'},{cursor:shadowCursor(request,-1)},{view:'summary',cursor:shadowCursor(request,1)}])
    await assert.rejects(()=>readDefenderShadow(client,{...request,...extra}));
  assert.equal(calls,0);
});
test('summary rejects missing, negative and inconsistent totals without converting them to zero',()=>{
  const s={records:0,openRemediation:0,critical:0,high:0,kev:0,exploitable:0,cveOpen:0,openEndpoint:0,openWeb:0,openExposure:0,
    uniqueOpenCves:0,affectedDeviceIds:0,affectedAssetKeys:0,bySeverity:{Critical:0,High:0,Medium:0,Low:0,Info:0},
    endpointByStatus:{Open:0,'In Remediation':0,'Risk Accepted':0,'False Positive':0,Resolved:0}};
  assert.equal(validShadowSummary(s,0),true);
  for(const bad of [null,{}, {...s,openEndpoint:1},{...s,critical:-1},{...s,endpointByStatus:{Open:0}}])assert.equal(validShadowSummary(bad,0),false);
});
