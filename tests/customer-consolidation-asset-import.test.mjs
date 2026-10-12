import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import ts from 'typescript';

async function assetUpsert() {
  const source=await readFile('lib/store.ts','utf8');
  const start=source.indexOf('function upsertAsset(');
  const end=source.indexOf('export type TidalImportResult',start);
  assert.ok(start>0 && end>start);
  const javascript=ts.transpileModule(source.slice(start,end),{
    compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None},
  }).outputText;
  return new Function('markDirty','nextId',`${javascript}\nreturn upsertAsset;`)(()=>{},()=>{throw Error('Unexpected new asset');});
}

test('CrowdStrike refresh preserves the canonical Automate asset and records its own observation',async()=>{
  const upsert=await assetUpsert();
  const automate={id:'A-1',companyId:'CO-229336',companyName:'Global Market Innovators, Inc.',
    source:'automate',identifier:'HOST-1',hostname:'HOST-1',externalId:'auto-1',os:'Automate OS',
    ipAddresses:['10.0.0.1'],owner:'Automate owner',tags:['automate'],exposure:'internal',criticality:'high',lastSynced:'old'};
  const assets=new Map([[automate.id,automate]]);
  const crowdstrike={...automate,source:'crowdstrike',identifier:'host-1',hostname:'host-1',
    externalId:'cs-1',os:'CrowdStrike OS',ipAddresses:['10.0.0.2'],owner:'CrowdStrike owner',tags:['crowdstrike']};
  delete crowdstrike.id;
  const result=upsert({assets},crowdstrike);
  assert.equal(result.id,'A-1');
  assert.equal(assets.size,1);
  assert.equal(automate.source,'automate');
  assert.equal(automate.os,'Automate OS');
  assert.equal(automate.externalId,'auto-1');
  assert.deepEqual(automate.ipAddresses,['10.0.0.1']);
  assert.equal(automate.crowdstrikeObservation.externalId,'cs-1');
  assert.equal(automate.crowdstrikeObservation.os,'CrowdStrike OS');
  assert.deepEqual(automate.crowdstrikeObservation.ipAddresses,['10.0.0.2']);
});
