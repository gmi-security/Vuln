import assert from 'node:assert/strict';
import test from 'node:test';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {sourceSelectionHash:hash,planCustomerSourceAuthority:plan}=require('../.worker-build/spotlight-summary/lib/customer-source-authority.js');
function binding(id,extra={}){
  const b={id,companyId:'CO-A',provider:'crowdstrike',domain:'endpoint-findings',authority:'findings-primary',originKey:'origin-a',mirrorOf:null,
    configured:true,sourcePresent:true,sourceFingerprint:'a'.repeat(64),reviewedSelectionHash:null,scopeVerified:true,reader:'spotlight-summary-v1',...extra};
  b.reviewedSelectionHash=hash(b);return b;
}
test('one reviewed source is ready for comparison, never activation or platform totals',()=>{
  for(const b of [binding('cs'),binding('df',{provider:'defender',reader:'defender-saved-v1'})]){
    const p=plan('CO-A',[b]);assert.equal(p.state,'ready-for-comparison');assert.deepEqual(p.proposedSources,[b.id]);
    assert.equal(p.canActivate,false);assert.equal(p.combinedPlatformFindings,null);assert.equal(p.observations[0].state,'not-loaded');
  }
});
test('a reviewed Elastic mirror contributes no second total or fallback',()=>{
  const cs=binding('cs'),es=binding('es',{provider:'elastic',authority:'mirror',mirrorOf:'cs',reader:null});
  const p=plan('CO-A',[es,cs],{cs:{companyId:'CO-A',source:'crowdstrike',state:'summary-pending'}});
  assert.equal(p.state,'ready-for-comparison');assert.deepEqual(p.proposedSources,['cs']);assert.deepEqual(p.excludedMirrors,['es']);
  assert.equal(p.observations[0].state,'summary-pending');assert.equal(p.combinedPlatformFindings,null);
  assert.equal(plan('CO-A',[es]).state,'needs-review');
});
test('wrong mirror origin, cycles, self-reference and cross-customer targets cannot establish authority',()=>{
  const cs=binding('cs');
  for(const b of [binding('es',{authority:'mirror',mirrorOf:'cs',originKey:'other'}),binding('es',{authority:'mirror',mirrorOf:'es'}),binding('es',{authority:'mirror',mirrorOf:'other-customer'})])assert.equal(plan('CO-A',[cs,b]).state,'needs-review');
  assert.equal(plan('CO-A',[binding('a',{authority:'mirror',mirrorOf:'b'}),binding('b',{authority:'mirror',mirrorOf:'a'})]).state,'needs-review');
  assert.equal(plan('CO-A',[binding('foreign',{companyId:'CO-B'}),binding('es',{authority:'mirror',mirrorOf:'foreign'})]).state,'needs-review');
});
test('multiple independent scanners need record correlation even if their totals happen to match',()=>{
  const p=plan('CO-A',[binding('cs'),binding('df',{provider:'defender',reader:'defender-saved-v1',originKey:'other'})]);
  assert.equal(p.state,'requires-record-correlation');assert.equal(p.combinedPlatformFindings,null);
  assert.equal(plan('CO-A',[binding('one'),binding('two')]).state,'needs-review');
});
test('scope, configuration, role and mirror changes invalidate selection review',()=>{
  const original=binding('cs');
  for(const changes of [{sourceFingerprint:'b'.repeat(64)},{authority:'mirror'},{originKey:'new-origin'},{mirrorOf:'other'},{reader:null}]){
    const p=plan('CO-A',[{...original,...changes}]);assert.equal(p.state,'needs-review');assert.ok(p.issues.some(i=>i.code==='selection-needs-review'));
  }
  for(const changes of [{scopeVerified:false},{configured:false},{sourcePresent:false},{reviewedSelectionHash:null}])assert.equal(plan('CO-A',[{...original,...changes}]).state,'needs-review');
});
test('inventory, web, exposures, enrichment and query tiles never become endpoint findings',()=>{
  const items=[['inventory','inventory'],['web-findings','findings-primary'],['exposures','unassigned'],['enrichment','enrichment'],['saved-queries','query-only'],['endpoint-findings','query-only']].map(([domain,authority],i)=>binding(String(i),{domain,authority}));
  const p=plan('CO-A',items);assert.equal(p.state,'no-findings-source');assert.equal(p.otherDomains.length,6);
  assert.deepEqual(p.proposedSources,[]);assert.equal(p.combinedPlatformFindings,null);
});
test('unsupported independent readers and unassigned endpoints block a complete selection',()=>{
  assert.equal(plan('CO-A',[binding('es',{provider:'elastic',reader:null})]).issues[0].code,'saved-reader-unavailable');
  assert.equal(plan('CO-A',[binding('cs'),binding('unknown',{authority:'unassigned'})]).state,'needs-review');
  assert.equal(plan('CO-A',[binding('forged',{provider:'nessus',reader:'defender-saved-v1'})]).state,'needs-review');
});
test('stale and failed latest imports retain their selected source with explicit observation state',()=>{
  const result={companyId:'CO-A',source:'crowdstrike',state:'available',generation:{id:'old-run',freshness:'stale'},projection:{state:'pending'},latestAttempt:{status:'failed'}};
  const p=plan('CO-A',[binding('cs')],{cs:result});assert.equal(p.state,'ready-for-comparison');
  assert.deepEqual(p.observations[0],{bindingId:'cs',provider:'crowdstrike',state:'available',generationId:'old-run',freshness:'stale',revisionMatches:null,summaryPending:true,latestAttempt:'failed'});
  const changed={...result,generation:{...result.generation,revisionMatches:false}};
  assert.equal(plan('CO-A',[binding('cs')],{cs:changed}).state,'needs-review');
});
test('customer separation, bounded input and wrong-customer observations fail closed',()=>{
  const p=plan('CO-A',[binding('foreign-binding',{companyId:'CO-B'})]);assert.equal(p.state,'no-findings-source');assert.doesNotMatch(JSON.stringify(p),/CO-B|foreign-binding/);
  for(const id of ['',null,'*'])assert.throws(()=>plan(id,[]));
  assert.throws(()=>plan('CO-A',Array(10001).fill(binding('x'))));
  assert.throws(()=>plan('CO-A',[binding('x'),binding('x')]));
  assert.throws(()=>plan('CO-A',[binding('cs')],{cs:{companyId:'CO-B',source:'crowdstrike'}}));
  assert.throws(()=>plan('CO-A',[binding('cs')],{cs:{companyId:'CO-A',source:'defender'}}));
});
