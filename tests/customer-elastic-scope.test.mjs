import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { loadElasticScope, loadConnectorPreview, loadConnectorReview, loadQueryRouting, loadConnectorStatus } from '../scripts/connector-preview-loader.mjs';
const scope = await loadElasticScope(), routing = await loadQueryRouting();
const names = ['logs-crowdstrike.vulnerability-alpha','logs-crowdstrike.discover_asset-alpha'];
test('approved scopes require bounded exact local names',()=>{
 assert.deepEqual(scope.elasticDatasets(names), [...names].sort());
 for(const value of [null,[],['*'],['logs-*'],['remote:logs'],['../logs'],['.ds-logs-001'],['a,b'],['A'],['a','a'],Array(101).fill('a')])
   assert.throws(()=>scope.elasticDatasets(value));
});
test('requested FROM patterns intersect only the reviewed dataset list',()=>{
 const output = scope.customerEsql('FROM *crowdstrike.vuln* METADATA _index, _id | STATS findings=COUNT(*)',names);
 assert.deepEqual(output.datasets,[names[0]]);assert.match(output.suffix,/METADATA _index, _id/);
 assert.deepEqual(scope.customerEsql('FROM logs-*, logs-crowdstrike.vulnerability-alpha | LIMIT 10',names).datasets,[...names].sort());
 assert.throws(()=>scope.customerEsql(`FROM ${'a*'.repeat(3000)}b | LIMIT 1`,['a'.repeat(200)]));
 assert.throws(()=>scope.customerEsql('FROM ab*bc | LIMIT 1',['abc']),'segments must not overlap');
 for(const from of ['foreign','logs-*, foreign','remote:*','<logs-{now/d}>','"logs-*"','* EXPLAIN','(FROM logs-*)','logs-* MODE time_series'])
   assert.throws(()=>scope.customerEsql(`FROM ${from} | STATS n=COUNT(*)`,names));
});
test('quoted pipes, CVE scoring, multivalues and dissection keep their meaning',()=>{
 const query='FROM logs-* | EVAL row = CONCAT("FROM | ENRICH ", "\\\"escaped\\\"", `host.name`) | DISSECT row "%{a}|%{b}" | EVAL offset=[0,1,2], risk=CASE(n>0, 1, 0) | MV_EXPAND offset | STATS n=COUNT(*) BY b | SORT n DESC | KEEP n,b';
 assert.ok(scope.customerEsql(query,names).suffix.includes('CONCAT("FROM | ENRICH "'));
 assert.ok(scope.customerEsql(query,names).suffix.endsWith('\n| KEEP n,b'));
 assert.equal(scope.customerEsql('// comment\nFROM logs-* // source note\n| LIMIT 1',names).suffix,'\n| LIMIT 1');
 assert.ok(scope.customerEsql('FROM logs-* | EVAL row=FROM_BASE64(value), `from`="value" | KEEP row',names));
});
test('existing bundled coverage and CVE severity queries remain compatible',async()=>{
 for(const file of ['asset-coverage.esql','unique-open-cves-severity.esql','unique-open-cves-severity-chart.esql']) {
   const query=await readFile(`n8n/elastic/${file}`,'utf8');assert.ok(scope.customerEsql(query,names));
 }
});
test('additional sources and lexical escapes are rejected before execution',()=>{
 for(const tail of ['LOOKUP JOIN foreign ON id','ENRICH foreign','FORK (WHERE true) (FROM foreign)',
   'EVAL x=(FROM foreign)','WHERE id IN (FROM foreign | KEEP id)','EVAL x="unfinished','EVAL x="""triple"""',
   'EVAL x="bad\\q"','EVAL x=1 /* hidden */','EVAL x=1; FROM foreign',
   'EVAL x=(1 | FROM foreign)','EVAL x=1 | FROM foreign','EVAL x=1 | ROW x=1','EVAL x=1 | PROMQL rate(foo)',
   'COMPLETION prompt WITH inference_id="external"','EVAL x=1 |','EVAL x=)1(','EVAL x=1\u0000'])
   assert.throws(()=>scope.customerEsql('FROM logs-* | '+tail,names),tail);
});
test('resolution pins streams to physical indexes; rejects aliases, missing and shared backing indexes',()=>{
 const body={indices:[{name:'index-a',attributes:['open']}],aliases:[],data_streams:[{name:'logs-a',backing_indices:['.ds-logs-a-000001','.ds-logs-a-000002']}]};
 assert.deepEqual(scope.resolvedElasticIndices(['index-a','logs-a'],body),['.ds-logs-a-000001','.ds-logs-a-000002','index-a']);
 for(const edit of [{aliases:[{name:'alias',indices:['foreign']}]},{indices:[]},{indices:[{name:'index-a',attributes:['closed']}]},
   {indices:[{name:'foreign',attributes:['open']}]},{indices:[{name:'index-a',attributes:['open'],data_stream:'foreign'}]},
   {data_streams:[{name:'logs-a',backing_indices:[]}]},{data_streams:[{name:'logs-a',backing_indices:['remote:foreign']}]},
   {data_streams:[{name:'logs-a',backing_indices:['index-a']}]},{data_streams:[{name:'logs-a',backing_indices:['.ds-x','.ds-x']}]},
   {indices:null}]) assert.throws(()=>scope.resolvedElasticIndices(['index-a','logs-a'],{...body,...edit}));
});
test('Elastic approval uses the saved connection revision and query-only exclusive datasets',async()=>{
 const build=await loadConnectorPreview(), review=await loadConnectorReview(), project=await loadConnectorStatus();
 const data={companies:[{id:'A',name:'Alpha'},{id:'B',name:'Beta'}],defender:[],spotlight:[],connections:[{source:'elastic',revision:3}],tiles:[]};
 const preview=build(data,{}), c=preview.candidates.find(c=>c.connectionRef==='dashboard:elastic_dashboard_connection:1'), hash=review.connectorDraftEvidence(c,preview.candidates).candidateHash;
 const row={candidate_id:c.id,company_id:'A',provider:'elastic',source_scope:JSON.stringify([...names].sort()),candidate_hash:hash,binding_hash:hash,imported_hash:hash,
   binding_revision:1,current_binding_revision:1,revision:1,enabled:true,source_present:true,review_state:'reviewed',reviewed_at:'2026-10-10',
   proposal:{companyId:'A',tenantId:null,authority:'query-only',targets:[],datasets:names}};
 assert.equal(routing.queryBindingScope('A',preview,row).connectionRevision,3);
 for(const change of [{tenantId:'tenant'},{authority:'mirror'},{targets:['host']},{datasets:['logs-*']},{datasets:[]}])
   assert.throws(()=>routing.queryBindingScope('A',preview,{...row,proposal:{...row.proposal,...change}}));
 assert.throws(()=>routing.queryBindingScope('A',build({...data,connections:[{source:'elastic',revision:4}]},{}),row));
 const status=routing.queryRoutingStatus(row,preview,'elastic'); assert.equal(status.review,'Query route approved');
 const out=project('A',preview,[{id:c.id,candidate:c,candidate_hash:hash,proposal:row.proposal,source_present:true,review_state:'reviewed',reviewed_at:row.reviewed_at}],true,undefined,[],[],[],[status]);
 assert.match(out.items[0].data.lifecycle,/approved datasets/);assert.doesNotMatch(JSON.stringify(out),/vulnerability-alpha|discover_asset-alpha/);
});
test('query provider switches are independent and invalid values fail closed',()=>{
 assert.equal(routing.reviewedQueryRouting('elastic','elastic'),true);assert.equal(routing.reviewedQueryRouting('elastic'),false);
 assert.equal(routing.reviewedQueryRouting('crowdstrike','elastic'),false);
 for(const provider of ['elastic','crowdstrike'])assert.equal(routing.reviewedQueryRouting('elastic, crowdstrike',provider),true);
 for(const raw of ['all','Elastic','elastic,','elastic,elastic','elastic,unknown'])assert.throws(()=>routing.reviewedQueryRouting(raw,'elastic'));
});
