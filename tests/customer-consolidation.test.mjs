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
  const scheduled=pair.flatMap((p,pairIndex)=>Array.from({length:4},(_,index)=>({
    id:`N-${pairIndex}-${index}`,companyId:p.sourceId,companyName:p.sourceName,
    folderId:pairIndex?'F-V-S':'F-G-S',nessusScanId:(pairIndex?5101:4101)+index,
    timestamp:1700000000000+pairIndex*100000+index*123,
  })));
  const buckets=new Map([
    ['companies:00',companies],
    ['folders:00',[row('F-G-S','CO-9150',{name:'General'}),row('F-G-D','CO-229336',{name:'General'}),row('F-V-S','CO-9153',{name:'General'}),row('F-V-D','CO-229438',{name:'General'})]],
    ['scans:00',[row('S-G','CO-9150',{companyName:'GMI Scans',folderId:'F-G-S',folderName:'General',connector:'nessus'}),row('S-V','CO-9153',{companyName:'Valor Global Scans',folderId:'F-V-S',folderName:'General',connector:'nessus'}),
      row('SCAN-140499','CO-9150',{companyName:'GMI Scans',folderId:'F-G-S',folderName:'General',connector:'vulners',externalRef:'vulners-bridge:CO-9150'}),
      row('SCAN-25239','CO-9150',{companyName:'GMI Scans',folderId:'F-G-S',folderName:'General',connector:'crowdstrike',externalRef:'spotlight:CO-9150'}),
      ...scheduled.map(s=>row(s.id,s.companyId,{companyName:s.companyName,folderId:s.folderId,folderName:'General',
        connector:'nessus',vendor:{nessusScanId:s.nessusScanId}}))]],
    ['findings:00',[row('V-G','CO-9150',{companyName:'GMI Scans',scanId:'S-G',asset:'host-g'}),row('V-V','CO-9153',{companyName:'Valor Global Scans',scanId:'S-V',asset:'host-v'}),
      row('V-G-VULNERS','CO-9150',{companyName:'GMI Scans',scanId:'SCAN-140499',asset:'host-g'}),
      row('V-G-SPOTLIGHT','CO-9150',{companyName:'GMI Scans',scanId:'SCAN-25239',asset:'host-g'}),
      row('V-G-NESSUS','CO-9150',{companyName:'GMI Scans',scanId:'N-0-0',asset:'host-g'}),
      row('V-V-NESSUS','CO-9153',{companyName:'Valor Global Scans',scanId:'N-1-0',asset:'host-v'})]],
    ['assets:00',[row('A-G','CO-9150',{companyName:'GMI Scans',identifier:'host-g',hostname:'host-g',source:'crowdstrike',os:'CS OS',externalId:'cs-1'}),row('A-G-D','CO-229336',{companyName:'Global Market Innovators, Inc.',identifier:'host-g',hostname:'host-g',source:'automate',os:'Automate OS',externalId:'auto-1'}),row('A-V','CO-9153',{companyName:'Valor Global Scans',identifier:'host-v',source:'crowdstrike'})]],
    ['meta',{counter:1000,identityAliases:[['CO-9150::host-g','CO-9150::ip-g'],['CO-9153::host-v','CO-9153::ip-v']],
      unrelatedTopLevel:{keep:'same'},meta:{unrelatedNested:{keep:'same'},nessusOffsetLastTriggered:{
        ...Object.fromEntries(scheduled.map(s=>[`${s.companyId}:${s.nessusScanId}`,s.timestamp])),
        'CO-OTHER:9001':42,
      }}}],
  ]);
  return buckets;
}
const records=(buckets,kind)=>[...buckets].filter(([key])=>key.startsWith(`${kind}:`)).flatMap(([,entries])=>entries);

test('approved pairs move records without changing IDs, orphaning scans, or overwriting Automate assets',()=>{
  const original=fixture(), untouched=structuredClone(original);
  const result=planCustomerConsolidation(original,pair);
  assert.deepEqual(original,untouched);
  assert.deepEqual(records(result.buckets,'scans').map(([id])=>id),records(original,'scans').map(([id])=>id));
  assert.deepEqual(records(result.buckets,'findings').map(([id])=>id),records(original,'findings').map(([id])=>id));
  assert.deepEqual(records(result.buckets,'companies').map(([id])=>id),['CO-229336','CO-229438']);
  const scans=Object.fromEntries(records(result.buckets,'scans'));
  assert.equal(scans['S-G'].companyId,'CO-229336');assert.equal(scans['S-G'].folderId,'F-G-D');
  assert.equal(scans['S-V'].companyId,'CO-229438');assert.equal(scans['S-V'].folderId,'F-V-D');
  assert.equal(scans['SCAN-140499'].externalRef,'vulners-bridge:CO-229336');
  assert.equal(scans['SCAN-25239'].externalRef,'spotlight:CO-229336');
  const findings=Object.fromEntries(records(result.buckets,'findings'));
  assert.equal(findings['V-G'].id,'V-G');assert.equal(findings['V-G'].scanId,'S-G');
  assert.equal(findings['V-G-VULNERS'].scanId,'SCAN-140499');
  assert.equal(findings['V-G-SPOTLIGHT'].scanId,'SCAN-25239');
  assert.equal(findings['V-G-VULNERS'].companyId,'CO-229336');
  assert.equal(findings['V-G-SPOTLIGHT'].companyId,'CO-229336');
  assert.equal(findings['V-G-NESSUS'].scanId,'N-0-0');
  assert.equal(findings['V-V-NESSUS'].scanId,'N-1-0');
  assert.equal(findings['V-G-NESSUS'].companyId,'CO-229336');
  assert.equal(findings['V-V-NESSUS'].companyId,'CO-229438');
  assert.deepEqual(result.lineage.scanExternalRefs,[
    {scanId:'SCAN-140499',sourceCompanyId:'CO-9150',destinationCompanyId:'CO-229336',connector:'vulners',externalRefBefore:'vulners-bridge:CO-9150',externalRefAfter:'vulners-bridge:CO-229336'},
    {scanId:'SCAN-25239',sourceCompanyId:'CO-9150',destinationCompanyId:'CO-229336',connector:'crowdstrike',externalRefBefore:'spotlight:CO-9150',externalRefAfter:'spotlight:CO-229336'},
  ]);
  const assets=Object.fromEntries(records(result.buckets,'assets'));
  assert.equal(assets['A-G-D'].os,'Automate OS');assert.equal(assets['A-G'],undefined);
  assert.equal(assets['A-G-D'].crowdstrikeObservation.assetId,'A-G');
  assert.equal(assets['A-G-D'].crowdstrikeObservation.externalId,'cs-1');
  assert.equal(assets['A-V'].companyId,'CO-229438');
  assert.equal(result.lineage.assets[0].source.id,'A-G');
  assert.equal(result.lineage.assets[0].destinationId,'A-G-D');
  assert.deepEqual(result.buckets.get('meta').identityAliases,[['CO-229336::host-g','CO-229336::ip-g'],['CO-229438::host-v','CO-229438::ip-v']]);
  const beforeTriggers=original.get('meta').meta.nessusOffsetLastTriggered;
  const afterTriggers=result.buckets.get('meta').meta.nessusOffsetLastTriggered;
  assert.equal(Object.keys(afterTriggers).length,Object.keys(beforeTriggers).length);
  for(const [sourceId,destinationId] of [['CO-9150','CO-229336'],['CO-9153','CO-229438']])
    for(const [key,timestamp] of Object.entries(beforeTriggers).filter(([key])=>key.startsWith(`${sourceId}:`))){
      assert.equal(afterTriggers[`${destinationId}:${key.split(':')[1]}`],timestamp);
      assert.equal(Object.hasOwn(afterTriggers,key),false);
    }
  assert.equal(afterTriggers['CO-OTHER:9001'],42);
  assert.deepEqual(result.buckets.get('meta').unrelatedTopLevel,original.get('meta').unrelatedTopLevel);
  assert.deepEqual(result.buckets.get('meta').meta.unrelatedNested,original.get('meta').meta.unrelatedNested);
  assert.equal(result.lineage.nessusOffsetLastTriggered.length,8);
  for(const entry of result.lineage.nessusOffsetLastTriggered){
    assert.equal(beforeTriggers[entry.sourceKey],entry.timestamp);
    assert.equal(afterTriggers[entry.destinationKey],entry.timestamp);
    assert.equal(entry.scanIds.length,1);
    assert.ok(records(original,'scans').some(([id])=>id===entry.scanIds[0]));
  }
  assert.equal(result.report.orphans.scanFolder,0);
});

test('scheduler keys reject malformed source keys and invalid timestamps',()=>{
  for(const bad of ['CO-9150:abc','CO-9150:0','CO-9150:04101','CO-9150:4101:extra','prefix:CO-9150:4101']){
    const snapshot=fixture(),triggers=snapshot.get('meta').meta.nessusOffsetLastTriggered;
    triggers[bad]=triggers['CO-9150:4101'];delete triggers['CO-9150:4101'];
    assert.throws(()=>planCustomerConsolidation(snapshot,pair),/scheduler key/i);
  }
  for(const bad of ['1700000000000',-1,1.5,Number.MAX_SAFE_INTEGER+1,NaN,Infinity]){
    const snapshot=fixture();snapshot.get('meta').meta.nessusOffsetLastTriggered['CO-9153:5101']=bad;
    assert.throws(()=>planCustomerConsolidation(snapshot,pair),/scheduler timestamp/i);
  }
  const missingEntry=fixture();delete missingEntry.get('meta').meta.nessusOffsetLastTriggered['CO-9153:5101'];
  assert.throws(()=>planCustomerConsolidation(missingEntry,pair),/scheduler count/i);
});

test('scheduler lineage includes every source-owned historical scan in deterministic order',()=>{
  const snapshot=fixture(),scans=snapshot.get('scans:00');
  for(const [id,companyId,folderId,nessusScanId] of [
    ['N-0-0-Z','CO-9150','F-G-S',4101],['N-0-0-A','CO-9150','F-G-S',4101],
    ['N-1-0-Z','CO-9153','F-V-S',5101],['N-1-0-A','CO-9153','F-V-S',5101],
  ]) scans.push(row(id,companyId,{folderId,folderName:'General',connector:'nessus',vendor:{nessusScanId}}));
  snapshot.get('findings:00').push(row('V-G-HISTORICAL','CO-9150',{scanId:'N-0-0-A',asset:'host-g'}));
  const reversed=structuredClone(snapshot);
  reversed.get('scans:00').reverse();
  const original=structuredClone(snapshot);
  const result=planCustomerConsolidation(snapshot,pair);
  const reversedResult=planCustomerConsolidation(reversed,pair);
  assert.deepEqual(snapshot,original);
  for(const [sourceKey,expectedIds,destinationKey] of [
    ['CO-9150:4101',['N-0-0','N-0-0-A','N-0-0-Z'],'CO-229336:4101'],
    ['CO-9153:5101',['N-1-0','N-1-0-A','N-1-0-Z'],'CO-229438:5101'],
  ]){
    const entry=result.lineage.nessusOffsetLastTriggered.find(item=>item.sourceKey===sourceKey);
    const reversedEntry=reversedResult.lineage.nessusOffsetLastTriggered.find(item=>item.sourceKey===sourceKey);
    assert.deepEqual(entry.scanIds,expectedIds);
    assert.deepEqual(reversedEntry.scanIds,expectedIds);
    assert.equal(entry.destinationKey,destinationKey);
    assert.equal(entry.timestamp,original.get('meta').meta.nessusOffsetLastTriggered[sourceKey]);
    assert.equal(result.buckets.get('meta').meta.nessusOffsetLastTriggered[destinationKey],entry.timestamp);
  }
  assert.deepEqual(records(result.buckets,'scans').map(([id])=>id),records(snapshot,'scans').map(([id])=>id));
  assert.deepEqual(records(result.buckets,'findings').map(([id])=>id),records(snapshot,'findings').map(([id])=>id));
  assert.equal(Object.fromEntries(records(result.buckets,'findings'))['V-G-HISTORICAL'].scanId,'N-0-0-A');
  assert.equal(result.buckets.get('meta').meta.nessusOffsetLastTriggered['CO-OTHER:9001'],42);
  assert.deepEqual(result.buckets.get('meta').meta.unrelatedNested,original.get('meta').meta.unrelatedNested);
});

test('scheduler entries require all historical Nessus scans to have source ownership and matching IDs',()=>{
  const missing=fixture();missing.get('scans:00').splice(missing.get('scans:00').findIndex(([id])=>id==='N-0-0'),1);
  missing.get('findings:00').splice(missing.get('findings:00').findIndex(([id])=>id==='V-G-NESSUS'),1);
  assert.throws(()=>planCustomerConsolidation(missing,pair),/scheduler scan ownership/i);
  const foreign=fixture();foreign.get('scans:00').find(([id])=>id==='N-0-0')[1].companyId='CO-229438';
  foreign.get('findings:00').splice(foreign.get('findings:00').findIndex(([id])=>id==='V-G-NESSUS'),1);
  assert.throws(()=>planCustomerConsolidation(foreign,pair),/scheduler scan ownership/i);
  const mixed=fixture();mixed.get('scans:00').push(row('N-0-0-VALID','CO-9150',
    {companyName:'GMI Scans',folderId:'F-G-S',folderName:'General',connector:'nessus',vendor:{nessusScanId:4101}}));
  mixed.get('scans:00').push(row('DUP-N','CO-229438',
    {companyName:'Valor Global, LLC',folderId:'F-V-D',folderName:'General',connector:'nessus',vendor:{nessusScanId:4101}}));
  assert.throws(()=>planCustomerConsolidation(mixed,pair),/scheduler scan ownership/i);
  const mismatched=fixture();mismatched.get('scans:00').push(row('N-0-0-MISMATCH','CO-9150',
    {companyName:'GMI Scans',folderId:'F-G-S',folderName:'General',connector:'nessus',vendor:{nessusScanId:4101}}));
  mismatched.get('scans:00').at(-1)[1].id='DIFFERENT-ID';
  assert.throws(()=>planCustomerConsolidation(mismatched,pair),/scheduler scan ownership/i);
});

test('scheduler destination keys must remain collision free',()=>{
  const collision=fixture();collision.get('meta').meta.nessusOffsetLastTriggered['CO-229336:4101']=99;
  assert.throws(()=>planCustomerConsolidation(collision,pair),/scheduler destination collision/i);
});

test('canonical scan external references must not collide with any existing scan',()=>{
  for(const [externalRef,connector] of [['vulners-bridge:CO-229336','vulners'],['spotlight:CO-229336','crowdstrike']]){
    const snapshot=fixture();
    snapshot.get('scans:00').push(row(`D-${connector}`,'CO-229336',
      {companyName:'Global Market Innovators, Inc.',folderId:'F-G-D',folderName:'General',connector,externalRef}));
    assert.throws(()=>planCustomerConsolidation(snapshot,pair),/externalRef collision/i);
  }
});

test('unapproved source references and changed scan identity fail closed',()=>{
  for(const change of [
    scan=>{scan.externalRef='vulners-bridge:CO-9150:extra';},
    scan=>{scan.connector='nessus';},
    scan=>{scan.companyId='CO-9153';scan.folderId='F-V-S';},
  ]){
    const snapshot=fixture();change(snapshot.get('scans:00').find(([id])=>id==='SCAN-140499')[1]);
    assert.throws(()=>planCustomerConsolidation(snapshot,pair),/unapproved scan externalRef/i);
  }
  const unknown=fixture();unknown.get('scans:00').push(row('SCAN-OTHER','CO-9150',
    {companyName:'GMI Scans',folderId:'F-G-S',folderName:'General',connector:'vulners',externalRef:'vulners-bridge:CO-9150'}));
  assert.throws(()=>planCustomerConsolidation(unknown,pair),/unapproved scan externalRef/i);
  const otherFormat=fixture();otherFormat.get('scans:00').find(([id])=>id==='S-G')[1].externalRef='nmap:CO-9150';
  assert.throws(()=>planCustomerConsolidation(otherFormat,pair),/unapproved scan externalRef/i);
  const spotlight=fixture();spotlight.get('scans:00').find(([id])=>id==='SCAN-25239')[1].externalRef='spotlight:CO-9150:extra';
  assert.throws(()=>planCustomerConsolidation(spotlight,pair),/unapproved scan externalRef/i);
  const missing=fixture();missing.get('scans:00').splice(missing.get('scans:00').findIndex(([id])=>id==='SCAN-25239'),1);
  assert.throws(()=>planCustomerConsolidation(missing,pair),/approved scan externalRef identity is missing/i);
  const foreign=fixture();foreign.get('scans:00').push(row('FOREIGN','CO-229438',
    {companyName:'Valor Global, LLC',folderId:'F-V-D',folderName:'General',connector:'crowdstrike',externalRef:'spotlight:CO-9150'}));
  assert.throws(()=>planCustomerConsolidation(foreign,pair),/unapproved scan externalRef/i);
  const note=fixture();note.get('scans:00').find(([id])=>id==='SCAN-25239')[1].note='Original CO-9150 reference';
  assert.throws(()=>planCustomerConsolidation(note,pair),/Unhandled legacy customer reference in scans/i);
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
