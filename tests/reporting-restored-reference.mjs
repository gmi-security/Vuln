// Independent legacy-model reference for retained-data parity checks.
export async function originalSections(source,reference,companyId,capturedAt){
 await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{
  const c=(await source.query("SELECT e->1 company FROM vuln_store,LATERAL jsonb_array_elements(data) e WHERE key='companies:00' AND e->>0=$1",[companyId])).rows[0].company;
  const input={findings:[],scans:[],assets:[],history:[]};
  for(const [kind,n] of [['findings',64],['scans',8],['assets',16]])for(let i=0;i<n;i++){
   // Independently project only fields consumed by the unchanged report.
   const select=kind==='findings'?`jsonb_build_object('id',f->'id','companyId',f->'companyId','cve',f->'cve','title',f->'title',
    'asset',f->'asset','status',f->'status','severity',f->'severity','realRisk',f->'realRisk','cvss',f->'cvss',
    'connector',f->'connector','seenBy',f->'seenBy','lastSeen',f->'lastSeen','assetSource',f->'assetSource',
    'kev',f->'kev','exploitAvailable',f->'exploitAvailable','enrichments',f->'enrichments')`:'f';
   const {rows}=await source.query(`SELECT ${select} record FROM vuln_store,LATERAL jsonb_array_elements(data) WITH ORDINALITY x(e,n),
    LATERAL(SELECT e->1 f) y WHERE key=$1 AND f->>'companyId'=$2 ORDER BY n`,[`${kind}:${String(i).padStart(2,'0')}`,companyId]);
   input[kind].push(...rows.map(r=>r.record));
  }
  input.history=(await source.query("SELECT ts,data FROM vuln_metrics_history WHERE company_id=$1 AND ts >= $2::timestamptz-interval '180 days' ORDER BY ts,id",[companyId,capturedAt])).rows.map(r=>({ts:r.ts.toISOString(),data:r.data}));
  const contributors=[...new Set(input.findings.map(f=>f.connector))].sort();
  input.findings.sort((a,b)=>b.realRisk-a.realRisk||b.cvss-a.cvss);
  input.scans.sort((a,b)=>b.createdAt>a.createdAt?1:-1);input.assets.sort((a,b)=>a.identifier.localeCompare(b.identifier));
  const model=reference({id:c.id,name:c.name},input.findings,input.scans,input.assets,input.history);
  await source.query('COMMIT');return {model,contributors,records:input.findings.length};
 }catch(error){await source.query('ROLLBACK');throw error;}
}
