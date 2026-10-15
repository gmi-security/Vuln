import assert from 'node:assert/strict';
import test from 'node:test';
import {mutationHarness,seed,asset,finding,clone,company} from './connector-mutation-harness.mjs';

test('asset updates persist only their actual customer-owned record and survive restart',async()=>{
 const data=seed();data.assets=[['A-1',asset()],['A-2',asset('A-2','CO-B')]];
 const h=await mutationHarness({disk:{value:data}}),foreign=clone(h.memory().assets.get('A-2'));
 const input={...asset(),os:'Updated OS'};delete input.id;
 h.store.upsertAsset(h.memory(),input);await h.flush();
 assert.deepEqual(h.lastScope(),{assets:['A-1']});
 assert.deepEqual(new Map(h.disk.value.assets).get('A-2'),foreign);
 const restarted=await mutationHarness({disk:h.disk});assert.equal(restarted.memory().assets.get('A-1').os,'Updated OS');
});

test('new asset saves its new ID and counter without a full comparison',async()=>{
 const h=await mutationHarness(),input={...asset()};delete input.id;
 const saved=h.store.upsertAsset(h.memory(),input);await h.flush();
 assert.deepEqual(h.lastScope(),{assets:[saved.id]});assert.equal(h.disk.value.counter,1001);
 const restarted=await mutationHarness({disk:h.disk});const second=restarted.store.upsertAsset(restarted.memory(),{...input,identifier:'host-2',hostname:'host-2',externalId:'device-2'});
 assert.notEqual(second.id,saved.id);await restarted.flush();assert.equal(restarted.disk.value.assets.length,2);
});

test('CrowdStrike observation saves the canonical Automate asset rather than a nonexistent source row',async()=>{
 const data=seed(),owner=company('CO-229336','GMI'),canonical={...asset(),companyId:owner.id,companyName:owner.name};
 data.companies.push([owner.id,owner]);data.assets=[['A-1',canonical]];
 const h=await mutationHarness({disk:{value:data}}),input={...canonical,source:'crowdstrike',externalId:'cs-1',os:'CS OS'};delete input.id;
 h.store.upsertAsset(h.memory(),input);await h.flush();
 assert.deepEqual(h.lastScope(),{assets:['A-1']});const saved=new Map(h.disk.value.assets).get('A-1');
 assert.equal(saved.source,'automate');assert.equal(saved.os,'Windows');assert.equal(saved.crowdstrikeObservation.os,'CS OS');
});

test('a corroborating assessment saves lastSeen even when the risk score is unchanged',async()=>{
 const data=seed();data.findings=[['F-1',finding()],['F-2',finding('F-2','CO-B')]];
 const h=await mutationHarness({disk:{value:data}}),f=h.memory().findings.get('F-1');
 Object.assign(f,h.store.riskFields(h.memory(),f));h.store.markDirty({findings:['F-1']});await h.flush();
 h.store.correlateFinding(h.memory(),f,{...f,connector:'vulners',lastSeen:'2026-10-15T12:00:00Z'});await h.flush();
 assert.deepEqual(h.lastScope(),{findings:['F-1']});const saved=new Map(h.disk.value.findings).get('F-1');
 assert.equal(saved.lastSeen,'2026-10-15T12:00:00Z');assert.deepEqual(saved.seenBy,['nessus','vulners']);
 assert.equal(new Map(h.disk.value.findings).get('F-2').lastSeen,'2026-10-01T00:00:00Z');
});

test('stale closure saves exactly the covered finding and preserves foreign or uncovered findings',async()=>{
 const data=seed();data.findings=[['F-1',finding()],['F-2',{...finding('F-2'),asset:'uncovered'}],['F-3',finding('F-3','CO-B')]];
 const h=await mutationHarness({disk:{value:data}}),s=h.memory();
 assert.equal(await h.store.closeStaleFindings(s,'CO-A','nessus',new Set([h.store.canonicalAssetKey(s,'CO-A','host-1')]),new Set(),'2026-10-15T12:00:00Z'),1);
 await h.flush();assert.deepEqual(h.lastScope(),{findings:['F-1']});
 assert.deepEqual(h.disk.value.findings.map(([id,f])=>[id,f.status]),[['F-1','Resolved'],['F-2','Open'],['F-3','Open']]);
});

test('identity linking persists metadata without asking for unrelated collection payloads',async()=>{
 const h=await mutationHarness();h.store.linkIdentities(h.memory(),'CO-A',['host-1','10.0.0.1']);await h.flush();
 assert.deepEqual(h.lastScope(),{});assert.ok(h.disk.value.identityAliases.length>0);
 const restarted=await mutationHarness({disk:h.disk});assert.equal(restarted.store.resolveIdentity(restarted.memory(),'CO-A','host-1'),restarted.store.resolveIdentity(restarted.memory(),'CO-A','10.0.0.1'));
});

test('explicit deletion and unknown mutations both preserve the complete committed result',async()=>{
 const data=seed();data.findings=[['F-1',finding()],['F-2',finding('F-2','CO-B')]];
 const h=await mutationHarness({disk:{value:data}});h.memory().findings.delete('F-1');h.store.markDirty({findings:['F-1']});await h.flush();
 assert.deepEqual(h.disk.value.findings.map(([id])=>id),['F-2']);
 h.memory().findings.get('F-2').title='Unknown writer update';h.store.markDirty();h.store.markDirty({scans:[]});await h.flush();
 assert.equal(h.lastScope(),undefined);assert.equal(h.disk.value.findings[0][1].title,'Unknown writer update');
});
