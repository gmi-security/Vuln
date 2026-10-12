// Disabled, dependency-injected comparison adapter. No route, schema initializer,
// store hydration, vendor API or ticket write is imported here.
import {readDefenderShadowCve,shadowCveRequest} from './defender-shadow-cve.mjs';
import {readDefenderPublication} from './defender-shadow-publication.mjs';
const fail=(message,status)=>{throw Object.assign(new Error(message),{status});};
const MAX_CONTEXT_BYTES=8*1024*1024;

async function boundedRows(client,sql,params,limit){
  const limited=`${sql} LIMIT ${limit}`;
  const {rows:[size]}=await client.query(`SELECT count(*)::int n,COALESCE(sum(octet_length(row_to_json(limited)::text)),0)::text bytes FROM (${limited}) limited`,params);
  if(Number(size.bytes)>MAX_CONTEXT_BYTES)fail('Saved CVE context exceeds the read limit; no partial result',413);
  if(limit===10001&&size.n===10001)fail('Too many saved ticket scopes; no partial exclusions',413);
  return (await client.query(limited,params)).rows;
}

export async function readSavedCveEnrichment(client,cve){
  if(typeof cve!=='string'||!/^CVE-\d{4}-\d{4,19}$/.test(cve))fail('Explicit enrichment CVE required',400);
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s';SET LOCAL idle_in_transaction_session_timeout='15s'");
    const {rows:[tables]}=await client.query("SELECT to_regclass('public.cve_enrichment') enrichment");
    const enrichment=tables.enrichment?(await boundedRows(client,`SELECT cve,cvss_score,cvss_severity,epss_probability,cisa_kev,
      active_exploitation,active_exploitation_source,active_exploitation_detail,updated_at FROM cve_enrichment WHERE cve=$1`,[cve],1))[0]??null:null;
    await client.query('COMMIT');
    return {enrichment,enrichmentState:!tables.enrichment?'unavailable':enrichment?'available':'not-recorded'};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}

export async function readSavedCveContext(client,{companyId,cve,assets}){
  if(typeof companyId!=='string'||!/^CO-[A-Za-z0-9-]{1,120}$/.test(companyId)||
    typeof cve!=='string'||!/^CVE-\d{4}-\d{4,19}$/.test(cve)||!Array.isArray(assets)||assets.length>10000||
    assets.some(asset=>typeof asset!=='string'||!asset))fail('Explicit CVE context scope required',400);
  const wanted=new Set(assets),excluded=new Set();
  const add=(cid,asset,issue)=>{if(cid===companyId&&issue===cve&&wanted.has(asset))excluded.add(JSON.stringify([companyId,asset,cve]));};
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s';SET LOCAL idle_in_transaction_session_timeout='15s'");
    const {rows:[tables]}=await client.query(`SELECT to_regclass('public.patch_ticket_requests') singles,to_regclass('public.patch_group_ticket_requests') groups`);
    if(!tables.singles||!tables.groups)fail('Saved ticket context is unavailable',503);
    const tickets=await boundedRows(client,`SELECT id,state,review_state,ticket_id,ticket_url,closed FROM patch_group_ticket_requests
      WHERE packet->>'appCompanyId'=$1 AND cves @> jsonb_build_array($2::text) ORDER BY prepared_at DESC,id DESC`,[companyId,cve],101);
    // Legacy single-ticket scopes are not consistently tagged with appCompanyId.
    // Preserve exact legacy identity matching; packet contents never leave this boundary.
    const singles=await boundedRows(client,`SELECT packet->'hostScope' hosts FROM patch_ticket_requests
      WHERE cve=$1 AND state IN ('creating','uncertain','created') AND closed=false`,[cve],10001);
    for(const row of singles){
      if(row.hosts!=null&&!Array.isArray(row.hosts))fail('Invalid saved single-ticket scope',409);
      for(const host of row.hosts??[]){try{const [cid,id]=JSON.parse(host);add(cid,id,cve);}catch{/* Invalid legacy identity establishes no match. */}}
    }
    const groups=await boundedRows(client,`SELECT packet->'deviceCves' devices FROM patch_group_ticket_requests
      WHERE cves @> jsonb_build_array($1::text) AND state IN ('creating','uncertain','created') AND closed=false`,[cve],10001);
    for(const row of groups){
      if(row.devices!=null&&!Array.isArray(row.devices))fail('Invalid saved group-ticket scope',409);
      for(const device of row.devices??[])if(device&&typeof device==='object')add(device.cid,device.hostId,device.cve);
    }
    await client.query('COMMIT');
    return {tickets:tickets.slice(0,100),moreTickets:tickets.length>100,excluded};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}

export function createShadowCustomerCveReader({enabled=false,resolveCustomer,bindings=[]}={}){
  // Configuration is supplied by trusted server code, never by the request.
  const configured=new Map();
  for(const binding of bindings){
    if(configured.has(binding.companyId))fail('Duplicate shadow customer binding',409);
    configured.set(binding.companyId,Object.freeze({...binding}));
  }
  return async function read({shadowClient,enrichmentClient,ticketClient},request){
    if(enabled!==true)fail('Shadow customer CVE reads are disabled',404);
    const binding=configured.get(request.companyId);
    if(!binding||binding.source!=='defender')fail('Customer source has no supported shadow CVE binding',409);
    if(Object.hasOwn(request,'projectionId')||Object.hasOwn(request,'selection'))fail('Comparison selection is controlled by trusted configuration',400);
    if(binding.selection!==undefined&&binding.selection!=='published')fail('Invalid comparison selection',409);
    if(binding.selection==='published'&&binding.projectionId!==undefined)fail('Ambiguous comparison selection',409);
    if(typeof request.companyId!=='string'||!/^CO-[A-Za-z0-9-]{1,120}$/.test(request.companyId)||
      typeof request.cve!=='string'||!/^CVE-\d{4}-\d{4,19}$/i.test(request.cve))fail('Choose a valid customer and CVE',400);
    const resolved=await resolveCustomer(request.companyId);
    if(resolved?.companyId!==request.companyId||resolved.company?.id!==request.companyId||resolved.company.isDemo||
      typeof resolved.company.name!=='string')fail('Customer not found',404);
    let publication;
    if(binding.selection==='published'){
      publication=await readDefenderPublication(shadowClient,request.companyId);
      if(publication.state!=='published')fail('No complete Defender comparison is published for this customer.',409);
    }
    const scope=shadowCveRequest({companyId:request.companyId,projectionId:publication?.projectionId??binding.projectionId,cve:request.cve});
    // Pin once. Immutable retained generations keep this CVE read consistent
    // if publication changes before detail/enrichment/ticket reads finish.
    const source=await readDefenderShadowCve(shadowClient,scope);
    const enrichment=await readSavedCveEnrichment(enrichmentClient,scope.cve);
    const context=await readSavedCveContext(ticketClient,{...scope,assets:[...new Set(source.findings.map(f=>f.asset))]});
    return {detail:{companyId:scope.companyId,cve:scope.cve,companyName:resolved.company.name,
      scope:source.scope,projectionId:source.projectionId,projectionModelVersion:source.projectionModelVersion,
      ...(publication?{publication:{revision:publication.revision,publishedAt:publication.publishedAt}}:{}),
      observedAt:source.observedAt,sourceObservations:{crowdstrike:null,platform:source.observedAt},
      sourceRun:source.sourceRun,snapshotSavedAt:source.snapshotSavedAt,
      findingCount:source.findingCount,deviceCount:source.deviceCount,hosts:source.hosts,
      ...enrichment,tickets:context.tickets,moreTickets:context.moreTickets},
      // Server-only preparation inputs; never serialize this object as the public panel response.
      preparation:{findings:source.findings,excluded:context.excluded}};
  };
}
