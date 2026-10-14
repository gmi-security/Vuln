import assert from 'node:assert/strict';
import test from 'node:test';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {summaryRetentionPolicy,createSpotlightSummaryRetention}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-retention.js');
test('retention defaults and bounds preserve a minimum rollback set',()=>{
  assert.deepEqual(summaryRetentionPolicy(),{keepRecent:90,maxAgeDays:365,keepJobs:100,jobAgeDays:90,batchSize:5});
  for(const bad of [null,[],{keepRecent:2},{keepRecent:366},{maxAgeDays:0},{batchSize:6},{keepJobs:1},{jobAgeDays:NaN},{keepRecent:undefined},{extra:1}])assert.throws(()=>summaryRetentionPolicy(bad));
});
test('retention rejects unscoped customers and invalid policy before a connection',async()=>{
  const service=createSpotlightSummaryRetention({connect:()=>assert.fail('must not connect')});
  for(const company of [undefined,null,123,'', '*','../other'])await assert.rejects(()=>service.run(company));
  await assert.rejects(()=>service.run('CO-A',{apply:'true'}));
  await assert.rejects(()=>service.run('CO-A',{policy:{batchSize:0}}));
});
