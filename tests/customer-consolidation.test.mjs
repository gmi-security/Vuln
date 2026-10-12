import assert from 'node:assert/strict';
import test from 'node:test';
import {planCustomerConsolidation} from '../lib/db/customer-consolidation.mjs';
import {platformBucket,platformCollections,platformRecord} from '../lib/db/platform-records.mjs';

const pair = [
  {sourceId:'CO-9150',sourceName:'GMI Scans',destinationId:'CO-229336',destinationName:'Global Market Innovators, Inc.'},
  {sourceId:'CO-9153',sourceName:'Valor Global Scans',destinationId:'CO-229438',destinationName:'Valor Global, LLC'},
];
const row=(id,companyId,extra={})=>[id,{id,companyId,...extra}];
function fixture(){
  const companies=pair.flatMap(p=>[[p.sourceId,{id:p.sourceId,name:p.sourceName}],[p.destinationId,{id:p.destinationId,name:p.destinationName}]]);
  const buckets=new Map([
    ['companies:00',companies],
    ['folders:00',[row('F-G-S','CO-9150',{name:'General'}),row('F-G-D','CO-229336',{name:'General'}),row('F-V-S','CO-9153',{name:'General'}),row('F-V-D','CO-229438',{name:'General'})]],
    ['scans:00',[row('S-G','CO-9150',{companyName:'GMI Scans',folderId:'F-G-S',folderName:'General',connector:'nessus'}),row('S-V','CO-9153',{companyName:'Valor Global Scans',folderId:'F-V-S',folderName:'General',connector:'nessus'})]],
    ['findings:00',[row('V-G','CO-9150',{companyName:'GMI Scans',scanId:'S-G',asset:'host-g'}),row('V-V','CO-9153',{companyName:'Valor Global Scans',scanId:'S-V',asset:'host-v'})]],
    ['assets:00',[row('A-G','CO-9150',{companyName:'GMI Scans',identifier:'host-g',hostname:'host-g',source:'crowdstrike',os:'CS OS',externalId:'cs-1'}),row('A-G-D','CO-229336',{companyName:'Global Market Innovators, Inc.',identifier:'host-g',hostname:'host-g',source:'automate',os:'Automate OS',externalId:'auto-1'}),row('A-V','CO-9153',{companyName:'Valor Global Scans',identifier:'host-v',source:'crowdstrike'})]],
    ['meta',{counter:1000,identityAliases:[['CO-9150::host-g','CO-9150::ip-g'],['CO-9153::host-v','CO-9153::ip-v']]}],
  ]);
  return buckets;
}
const records=(buckets,kind)=>[...buckets].filter(([key])=>key.startsWith(`${kind}:`)).flatMap(([,entries])=>entries);

test('approved pairs move records without changing IDs, orphaning scans, or overwriting Automate assets',()=>{
  const original=fixture(), untouched=structuredClone(original);
  const result=planCustomerConsolidation(original,pair);
  assert.deepEqual(original,untouched);
  assert.deepEqual(records(result.buckets,'companies').map(([id])=>id),['CO-229336','CO-229438']);
  const scans=Object.fromEntries(records(result.buckets,'scans'));
  assert.equal(scans['S-G'].companyId,'CO-229336');assert.equal(scans['S-G'].folderId,'F-G-D');
  assert.equal(scans['S-V'].companyId,'CO-229438');assert.equal(scans['S-V'].folderId,'F-V-D');
  const findings=Object.fromEntries(records(result.buckets,'findings'));
  assert.equal(findings['V-G'].id,'V-G');assert.equal(findings['V-G'].scanId,'S-G');
  const assets=Object.fromEntries(records(result.buckets,'assets'));
  assert.equal(assets['A-G-D'].os,'Automate OS');assert.equal(assets['A-G'],undefined);
  assert.equal(assets['A-G-D'].crowdstrikeObservation.assetId,'A-G');
  assert.equal(assets['A-G-D'].crowdstrikeObservation.externalId,'cs-1');
  assert.equal(assets['A-V'].companyId,'CO-229438');
  assert.equal(result.lineage.assets[0].source.id,'A-G');
  assert.equal(result.lineage.assets[0].destinationId,'A-G-D');
  assert.deepEqual(result.buckets.get('meta').identityAliases,[['CO-229336::host-g','CO-229336::ip-g'],['CO-229438::host-v','CO-229438::ip-v']]);
  assert.equal(result.report.orphans.scanFolder,0);
});

test('missing folder and alias collisions stop without changing the source snapshot',()=>{
  const missing=fixture();missing.get('folders:00').splice(0,1);
  assert.throws(()=>planCustomerConsolidation(missing,pair),/folder/i);
  const collision=fixture();collision.get('meta').identityAliases.push(['CO-229336::host-g','CO-229336::other']);
  assert.throws(()=>planCustomerConsolidation(collision,pair),/alias/i);
});

test('a reference to an overlapping source asset ID blocks deletion',()=>{
  const snapshot=fixture();
  snapshot.get('findings:00')[0][1].assetId='A-G';
  assert.throws(()=>planCustomerConsolidation(snapshot,pair),/asset ID is referenced/i);
});
test('only the two reviewed General folder collisions may be deduplicated',()=>{
  const snapshot=fixture();
  snapshot.get('folders:00').push(row('F-OTHER-S','CO-9150',{name:'Nessus'}));
  snapshot.get('folders:00').push(row('F-OTHER-D','CO-229336',{name:'Nessus'}));
  assert.throws(()=>planCustomerConsolidation(snapshot,pair),/folder-name collision/i);
});

test('planned buckets can pass the SQL record adapter and reverse to the same legacy payload',()=>{
  const source=fixture(),bucketed=new Map([['meta',source.get('meta')]]);
  for(const [kind,config] of Object.entries(platformCollections)){
    const entries=records(source,kind);
    for(let i=0;i<config.buckets;i++)bucketed.set(`${kind}:${String(i).padStart(2,'0')}`,
      entries.filter(([id])=>platformBucket(id,config.buckets)===i));
  }
  const planned=planCustomerConsolidation(bucketed,pair).buckets;
  for(const [kind,config] of Object.entries(platformCollections)){
    for(let i=0;i<config.buckets;i++){
      const key=`${kind}:${String(i).padStart(2,'0')}`;
      for(const [order,entry] of planned.get(key).entries()){
        const row=platformRecord(kind,entry,(order+1)*1024);
        assert.equal(row.store_bucket,i);
        assert.equal(row.id,entry[0]);
      }
    }
  }
  const reversed=new Map(JSON.parse(JSON.stringify([...planned])));
  assert.deepEqual(reversed,planned);
  assert.deepEqual(reversed.get('meta').customerConsolidation.mappings,
    [{sourceId:'CO-9150',destinationId:'CO-229336'},
      {sourceId:'CO-9153',destinationId:'CO-229438'}]);
});
