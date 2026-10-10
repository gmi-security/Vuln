import assert from 'node:assert/strict';
import test from 'node:test';
import { parseRegistryArgs, registryReviewInput, exportRegistryDrafts, registryFailure } from '../scripts/customer-connector-registry.mjs';

test('operator command requires explicit scope and rejects activation, credentials and duplicate options', () => {
  const hash='a'.repeat(64);
  assert.equal(parseRegistryArgs(['import','--fingerprint',hash]).command,'import');
  assert.equal(parseRegistryArgs(['export','--company','CO-A','--output','private.json']).options['--company'],'CO-A');
  assert.equal(parseRegistryArgs(['export-bindings','--company','CO-A','--output','private.json']).command,'export-bindings');
  assert.equal(parseRegistryArgs(['assign','--input','review.json']).command,'assign');
  for(const args of [[],['activate'],['import'],['export','--output','private.json'],['review'],['assign'],['export-bindings','--output','private.json'],
    ['review','--input','a','--input','b'],['import','--fingerprint',hash,'--actor','admin'],
    ['review','--input','a','--private-key','SECRET']]) assert.throws(()=>parseRegistryArgs(args));
});
test('review input cannot override actor, source evidence or activation state', () => {
  const input={id:'a'.repeat(64),expectedRevision:1,candidateHash:'b'.repeat(64),decision:'save-draft',proposal:{},note:'Scope reviewed'};
  assert.deepEqual(registryReviewInput(input),input);
  for(const extra of [{actor:'admin'},{enabled:true},{candidate:{}},{privateKey:'SECRET'}])assert.throws(()=>registryReviewInput({...input,...extra}));
  for(const input of [null,[],{},'value'])assert.throws(()=>registryReviewInput(input));
});
test('private export suggests the selected customer but defaults to an inactive draft and does not export audit payloads', () => {
  const rows=[{id:'a',candidate_hash:'hash',revision:1,source_present:true,review_state:'pending-review',reviewed_by:'NOT_EXPORTED',
    candidate:{provider:'spiderfoot',connectionRef:'environment:scanner:spiderfoot',evidence:'shared-configuration',capabilities:['scan'],configured:true,review:['customer-target-scope-not-assigned']},
    proposal:{companyId:null,tenantId:null,datasets:[],targets:[],authority:'unassigned'},source_evidence:[{secret:'NOT_EXPORTED'}]}];
  const output=exportRegistryDrafts('CO-A',rows);
  assert.equal(output.drafts[0].reviewRequest.proposal.companyId,'CO-A');
  assert.equal(output.drafts[0].reviewRequest.decision,'save-draft');assert.equal(output.drafts[0].enabled,false);
  assert.equal(rows[0].proposal.companyId,null);assert.doesNotMatch(JSON.stringify(output),/NOT_EXPORTED/);
});
test('failure output explains stale proposals but redacts raw SQL, credentials and filesystem errors', () => {
  assert.match(registryFailure(new Error('Source metadata changed; import a fresh preview before reviewing.')),/fresh preview/);
  assert.match(registryFailure({code:'42P01'}),/does not create tables/);
  assert.match(registryFailure({code:'EEXIST'}),/already exists/);
  assert.doesNotMatch(registryFailure(new Error('password=SECRET at /private/secret-file')),/SECRET|secret-file/);
});
