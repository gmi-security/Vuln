import assert from 'node:assert/strict';
import test from 'node:test';
import {argumentsFor,digest,coreCounts,verifiedExternalIdentities,validateManifest} from '../scripts/consolidate-approved-customers.mjs';

const base=['--socket','/home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket',
 '--database','recovery_merge','--port','55483','--user','codex'];
test('private clone is the only accepted migration target and commit needs a reviewed plan',()=>{
 assert.equal(argumentsFor(['--inspect',...base]).mode,'--inspect');
 assert.throws(()=>argumentsFor(['--inspect',...base.map(v=>v==='recovery_merge'?'vuln':v)]),/private/);
 assert.throws(()=>argumentsFor(['--inspect',...base.map(v=>v==='55483'?'5432':v)]),/private/);
 assert.throws(()=>argumentsFor(['--commit',...base,'--manifest','review.json']),/plan hash/);
 assert.equal(argumentsFor(['--dry-run',...base,'--manifest','review.json']).mode,'--dry-run');
});
test('vendor numeric IDs stay unverified until independent evidence is supplied',()=>{
 assert.equal(verifiedExternalIdentities(null),false);
 assert.equal(verifiedExternalIdentities([{destinationId:'CO-229336',connectwise:{numericId:229336}}]),false);
 const manifest={version:1,mappings:[
  {sourceId:'CO-9150',sourceName:'GMI Scans',destinationId:'CO-229336',destinationName:'Global Market Innovators, Inc.'},
  {sourceId:'CO-9153',sourceName:'Valor Global Scans',destinationId:'CO-229438',destinationName:'Valor Global, LLC'}],
  expected:{snapshotSha256:'unobserved'},externalVerification:null};
 assert.doesNotThrow(()=>validateManifest('--dry-run',manifest));
 assert.throws(()=>validateManifest('--commit',manifest),/independent/i);
});
test('snapshot and count evidence changes when one source record changes',()=>{
 const snapshot=new Map([['companies:00',[]],['scans:00',[
  ['S1',{id:'S1',companyId:'CO-9150'}]]],['meta',{}]]);
 const before=digest(snapshot),counts=coreCounts(snapshot);
 assert.equal(counts['CO-9150'].source.scans,1);
 snapshot.get('scans:00')[0][1].companyId='CO-229336';
 assert.notEqual(digest(snapshot),before);
 assert.equal(coreCounts(snapshot)['CO-9150'].source.scans,0);
});
