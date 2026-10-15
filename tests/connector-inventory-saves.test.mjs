import assert from 'node:assert/strict';
import test from 'node:test';
import {mutationHarness,seed,asset,finding,clone} from './connector-mutation-harness.mjs';
const now='2026-10-15T12:00:00Z';
const device={...asset(),criticality:'High',exposure:'Internet-facing'};
delete device.id;delete device.companyId;delete device.companyName;delete device.lastSynced;
async function initial(){
 const data=seed();data.companies[0][1].kind='internal';
 data.assets=[['A-1',asset()],['A-2',asset('A-2','CO-B')]];
 data.findings=[['F-1',finding()],['F-2',{...finding('F-2'),connector:'defender'}],['F-3',finding('F-3','CO-B')]];
 const h=await mutationHarness({disk:{value:data},now});
 for(const f of h.memory().findings.values())h.store.rescoreFinding(h.memory(),f);
 await h.flush();return clone(h.disk.value);
}
for(const source of ['tidal','automate','crowdstrike','intune'])for(const reviewed of [false,true]){
 test(`${source} ${reviewed?'reviewed':'legacy'} inventory saves affected cross-source scores and matches a full-save oracle`,async()=>{
  const data=await initial(),route={companyId:'CO-A',sourceScope:source==='intune'?'tenant-1':'vendor-a',connectionRef:'environment:FALCON',provider:source};
  const providers={
   'lib/customer-inventory-routing-server.ts':{loadReviewedInventoryRoutes:async()=>reviewed?[route]:null},
   'lib/connectwise-automate.ts':{automateConfig:()=>({}),automateListClients:async()=>[{id:'vendor-a',name:'Alpha'}],automateListComputers:async()=>[device]},
   'lib/crowdstrike.ts':{falconConfigs:()=>[{sourceRef:'environment:FALCON',customerName:'Alpha',label:'Fixture'}],falconListAssets:async()=>[device]},
   'lib/intune.ts':{intuneConfig:()=>({tenantId:'tenant-1'}),intuneListAssets:async()=>[device]},
  };
  const run=async baseline=>{
   const h=await mutationHarness({disk:{value:clone(data)},providers,baseline,now});let result;
   if(source==='tidal')result=await h.store.applyTidalInventory([{...device,customer:'Alpha',sourceCompanyId:'vendor-a'}],undefined,reviewed?[route]:undefined);
   else result=await h.store[source==='automate'?'importFromAutomate':source==='intune'?'importFromIntune':'importFromCrowdstrike']();
   assert.equal(result.error,undefined);await h.flush();h.assertPersisted();return h;
  };
  const h=await run(false),oracle=await run(true);
  const scope=h.lastScope();assert.notEqual(scope,undefined);assert.deepEqual(scope.assets,['A-1']);assert.deepEqual(scope.findings,['F-1','F-2']);
  assert.deepEqual(h.disk.value,oracle.disk.value);
  assert.deepEqual(new Map(h.disk.value.findings).get('F-3'),new Map(data.findings).get('F-3'));
  assert.deepEqual(new Map(h.disk.value.assets).get('A-2'),new Map(data.assets).get('A-2'));
  const restarted=await mutationHarness({disk:h.disk,providers,now});restarted.assertPersisted();
  // Same inventory observations still persist; identical risk fields need no record serialization.
  if(source==='tidal')await restarted.store.applyTidalInventory([{...device,customer:'Alpha',sourceCompanyId:'vendor-a'}],undefined,reviewed?[route]:undefined);
  else await restarted.store[source==='automate'?'importFromAutomate':source==='intune'?'importFromIntune':'importFromCrowdstrike']();
  await restarted.flush();restarted.assertPersisted();assert.deepEqual(restarted.lastScope().assets,['A-1']);assert.equal(restarted.lastScope().findings,undefined);
 });
}
test('Automate partial customer fetch preserves completed changes without touching the failed customer',async()=>{
 const data=await initial();const providers={
  'lib/customer-inventory-routing-server.ts':{loadReviewedInventoryRoutes:async()=>null},
  'lib/connectwise-automate.ts':{automateConfig:()=>({}),automateListClients:async()=>[{id:'a',name:'Alpha'},{id:'b',name:'Beta'}],automateListComputers:async(c,id)=>{if(id==='b')throw Error('Provider failed');return [device];}},
 };
 const h=await mutationHarness({disk:{value:data},providers,now});const result=await h.store.importFromAutomate();
 assert.equal(result.errors.length,1);h.assertPersisted();assert.deepEqual(h.lastScope().findings,['F-1','F-2']);
 assert.equal(new Map(h.disk.value.assets).get('A-2').lastSynced,'2026-10-01T00:00:00Z');
});
