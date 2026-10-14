import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
import {loadElasticScope} from '../scripts/connector-preview-loader.mjs';
const scope=await loadElasticScope();
class DashboardError extends Error {constructor(message,status=400){super(message);this.status=status;}}
let replies=[],calls=[],executions=[],result={columns:[{name:'n',type:'long'}],rows:[[2]],truncated:false},queryFailure=false;
const run=async(kind,connection,query)=>{executions.push({kind,connection,query});if(queryFailure)throw new DashboardError('mock outage');return result;};
const dependencies={
 './elastic-dashboard':{DashboardError},'./customer-elastic-scope':scope,
 './elastic-query-client':{elasticJsonRequest:async(connection,path,method)=>{calls.push({connection,path,method});assert.ok(replies.length,'Unexpected request');const r=replies.shift();if(r instanceof Error)throw r;return r;},executeEsql:(...args)=>run('sync',...args)},
 './elastic-async-client':{executeEsqlAsync:(...args)=>run('async',...args)},
};
const mod=new SourceTextModule(ts.transpileModule(await readFile('lib/customer-elastic-query.ts','utf8'),{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText);
await mod.link(name=>{const values=dependencies[name];assert.ok(values,'unexpected import');return new SyntheticModule(Object.keys(values),function(){for(const [key,value] of Object.entries(values))this.setExport(key,value);});});
await mod.evaluate();const api=mod.namespace;
const connection={endpoint:'https://example.invalid',apiKey:'fake-test-key'},stack={body:{version:{build_flavor:'default',number:'9.3.0'}}};
const resolved={body:{indices:[],aliases:[],data_streams:[{name:'logs-alpha',backing_indices:['.ds-logs-alpha-000001']}]}};
function reset(){calls=[];executions=[];replies=[];queryFailure=false;}
test('reviewed sync and async execution pin only resolved physical indexes and report restricted scope',async()=>{
 for(const background of [true,false]){
  reset();replies=[stack,resolved];const out=await api.executeCustomerEsql(connection,'FROM logs-* | STATS n=COUNT(*)',background,['logs-alpha']);
  assert.deepEqual(calls.map(c=>[c.method,c.path]),[['GET','/'],['GET','/_resolve/index/logs-alpha?expand_wildcards=none']]);
  assert.equal(executions[0].query,'FROM ".ds-logs-alpha-000001"\n| STATS n=COUNT(*)');
  assert.equal(executions[0].kind,background?'async':'sync');assert.match(out.note,/approved datasets/);assert.deepEqual(out.rows,[[2]]);
 }
});
test('unsupported query never makes a source call',async()=>{
 for(const query of ['FROM foreign | LIMIT 1','FROM logs-* | LOOKUP JOIN foreign ON id','FROM logs-* | WHERE id IN (FROM foreign)']){
  reset();await assert.rejects(()=>api.executeCustomerEsql(connection,query,true,['logs-alpha']));assert.equal(calls.length,0);assert.equal(executions.length,0);
 }
});
test('missing resolution privileges, alias resolution, unknown deployment and warnings never execute a query',async()=>{
 for(const response of [new DashboardError('Elastic rejected the API key or its index permissions.'),{body:{indices:[],data_streams:[],aliases:[{name:'logs-alpha',indices:['foreign']}]}},{...resolved,warning:true},{body:{indices:[],aliases:[],data_streams:[]}}]){
  reset();replies=[stack,response];await assert.rejects(()=>api.executeCustomerEsql(connection,'FROM logs-* | LIMIT 1',true,['logs-alpha']));assert.equal(executions.length,0);
 }
 for(const version of [{build_flavor:'serverless',number:'9.3.0'},{build_flavor:'default',number:'unknown'},undefined]){
  reset();replies=[{body:{version}}];await assert.rejects(()=>api.executeCustomerEsql(connection,'FROM logs-* | LIMIT 1',true,['logs-alpha']),/Stack deployment/);assert.equal(calls.length,1);assert.equal(executions.length,0);
 }
});
test('connection validation reads only deployment metadata and query failures retain errors',async()=>{
 reset();replies=[stack];await api.checkReviewedElasticConnection(connection);assert.equal(calls[0].path,'/');assert.equal(executions.length,0);
 reset();replies=[stack,resolved];queryFailure=true;await assert.rejects(()=>api.executeCustomerEsql(connection,'FROM logs-* | LIMIT 1',true,['logs-alpha']),/mock outage/);
});
