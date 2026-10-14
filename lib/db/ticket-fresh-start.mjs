import {createHash} from 'node:crypto';
export const ticketHistorySchema='patch_ticket_history_vuln2';
export const ticketTables=Object.freeze(['patch_ticket_requests','patch_ticket_audit','patch_group_ticket_requests','patch_group_ticket_audit']);
const q=value=>'"'+String(value).replaceAll('"','""')+'"';
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const protectedNames=['patch_connectwise_connection','patch_customer_routing','defender_connections',
 'dashboard_source_connections','elastic_dashboard_connection','elastic_dashboard_queries','reporting_company_links',
 'customer_connector_drafts','customer_connector_bindings','customer_source_selections','customer_inventory_routes',
 'customer_spotlight_routes','customer_scanner_routes','customer_query_routes','customer_appsec_routes','app_companies','app_store_metadata'];
async function grantsFor(client,relation,kind='r'){
 return (await client.query(`SELECT CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END grantee,x.privilege_type privilege,x.is_grantable grantable
  FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault($2::"char",c.relowner))) x WHERE c.oid=$1::regclass ORDER BY 1,2`,[relation,kind])).rows;
}
async function preserveGrants(client,relation,grants,kind='r'){
 const role=name=>name==='PUBLIC'?'PUBLIC':q(name),type=kind==='S'?'SEQUENCE':'TABLE';
 for(const grantee of new Set((await grantsFor(client,relation,kind)).map(g=>g.grantee)))await client.query(`REVOKE ALL ON ${type} ${relation} FROM ${role(grantee)}`);
 for(const grant of grants){
  if(!['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN','USAGE'].includes(grant.privilege))throw Error('Unknown relation privilege');
  await client.query(`GRANT ${grant.privilege} ON ${type} ${relation} TO ${role(grant.grantee)}${grant.grantable?' WITH GRANT OPTION':''}`);
 }
}
async function configurationFingerprint(client){
 const result=[];
 for(const name of protectedNames){
  if(!(await client.query('SELECT to_regclass($1) present',['public.'+name])).rows[0].present){result.push({name,exists:false});continue;}
  const row=(await client.query(`SELECT count(*)::text count,md5(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text)) hash FROM public.${q(name)} t`)).rows[0];
  result.push({name,...row});
 }
 // Legacy customer/config metadata is separate from the large finding buckets.
 if((await client.query("SELECT to_regclass('public.vuln_store') present")).rows[0].present){
  result.push({name:'vuln_store customer metadata',...(await client.query("SELECT count(*)::text count,md5(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY key)) hash FROM public.vuln_store t WHERE key='meta' OR key ~ '^companies:[0-9]+$'")).rows[0]});
 }
 return digest(result);
}
// Caller owns the read-only transaction for a consistent preview.
export async function inspectTicketFreshStart(client){
 if((await client.query('SELECT 1 FROM pg_namespace WHERE nspname=$1',[ticketHistorySchema])).rowCount)throw Error('Ticket history schema already exists; refuse repeat retirement');
 const identity=(await client.query("SELECT current_database() database,current_user role,inet_server_addr()::text address,inet_server_port() port,(SELECT oid::text FROM pg_database WHERE datname=current_database()) database_oid")).rows[0];
 const tables=[];
 for(const name of ticketTables){
  const relation=(await client.query(`SELECT c.oid::text oid,pg_get_userbyid(c.relowner) owner,c.relkind,c.relrowsecurity rls,c.relacl::text acl
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1`,[name])).rows[0];
  if(!relation||relation.relkind!=='r'||relation.rls)throw Error('Expected ordinary ticket table: '+name);
  const oid=relation.oid;
  if((await client.query("SELECT 1 FROM pg_constraint WHERE contype='f' AND (conrelid=$1::oid OR confrelid=$1::oid)",[oid])).rowCount)throw Error('Ticket foreign keys require independent review');
  if((await client.query("SELECT 1 FROM pg_depend WHERE refobjid=$1::oid AND classid='pg_rewrite'::regclass UNION ALL SELECT 1 FROM pg_trigger WHERE tgrelid=$1::oid AND NOT tgisinternal UNION ALL SELECT 1 FROM pg_inherits WHERE inhparent=$1::oid OR inhrelid=$1::oid",[oid])).rowCount)throw Error('Ticket dependencies require independent review');
  const columns=(await client.query(`SELECT a.attname name,a.attidentity identity,COALESCE(cardinality(a.attacl),0)>0 column_acl,pg_get_expr(d.adbin,d.adrelid) expression,
   pg_get_serial_sequence($2,a.attname) sequence FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid=$1::oid AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`,[oid,'public.'+name])).rows;
  for(const column of columns){
   if(column.column_acl)throw Error('Ticket column permissions require independent review');
   if(column.identity)throw Error('Identity ticket sequences require independent review');
   if(column.expression?.includes('nextval(')&&!column.sequence)throw Error('Unowned ticket sequence requires review');
   if(column.sequence){
    const sequence=(await client.query(`SELECT seqtypid::regtype::text type,seqstart::text start,seqincrement::text increment,
     seqmin::text min,seqmax::text max,seqcache::text cache,seqcycle cycle FROM pg_sequence WHERE seqrelid=$1::regclass`,[column.sequence])).rows[0];
    if(column.sequence!=='public.'+name+'_'+column.name+'_seq'||sequence?.type!=='bigint'||sequence.start!=='1'||
     sequence.increment!=='1'||sequence.min!=='1'||sequence.max!=='9223372036854775807'||sequence.cache!=='1'||sequence.cycle)
     throw Error('Nonstandard ticket sequence requires independent review');
    column.grants=await grantsFor(client,column.sequence,'S');
   }
  }
  const counts=(await client.query(`SELECT count(*)::text count,max(${name.endsWith('_audit')?'id':'updated_at'})::text latest FROM public.${q(name)}`)).rows[0];
  const grants=await grantsFor(client,'public.'+q(name));
  const indexes=(await client.query('SELECT indexname,indexdef FROM pg_indexes WHERE schemaname=$1 AND tablename=$2 ORDER BY indexname',['public',name])).rows;
  tables.push({name,...relation,...counts,columns,grants,indexes});
 }
 const plan={identity,archiveSchema:ticketHistorySchema,tables,configurationHash:await configurationFingerprint(client)};
 return {...plan,planHash:digest(plan)};
}
export async function applyTicketFreshStart(client,{writersStopped=false,expectedPlanHash}={}){
 if(writersStopped!==true)throw Error('All writers must be stopped before ticket retirement');
 if(!/^[a-f0-9]{64}$/.test(expectedPlanHash??''))throw Error('An exact observed plan hash is required');
 let open=false;
 try{
  await client.query("BEGIN; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='60s'; SET LOCAL search_path=public");open=true;
  await client.query('SELECT pg_advisory_xact_lock(20261014,2)');
  if((await client.query("SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'")).rowCount)throw Error('Stop other database sessions before ticket retirement');
  await client.query(`LOCK TABLE ${ticketTables.map(t=>'public.'+q(t)).join(',')} IN ACCESS EXCLUSIVE MODE`);
  const plan=await inspectTicketFreshStart(client);
  if(plan.planHash!==expectedPlanHash)throw Error('Ticket retirement plan changed; inspect again');
  if(plan.tables.some(t=>t.owner!==plan.identity.role))throw Error('Use the existing ticket table owner');
  await client.query(`CREATE SCHEMA ${q(ticketHistorySchema)}`);
  await client.query(`REVOKE ALL ON SCHEMA ${q(ticketHistorySchema)} FROM PUBLIC`);
  for(const table of plan.tables){
   await client.query(`ALTER TABLE public.${q(table.name)} SET SCHEMA ${q(ticketHistorySchema)}`);
   await client.query(`CREATE TABLE public.${q(table.name)} (LIKE ${q(ticketHistorySchema)}.${q(table.name)} INCLUDING ALL)`);
   // Preserve explicit names too: the normal app initializer uses IF NOT EXISTS
   // by index name and would otherwise create duplicate secondary indexes.
   const freshIndexes=(await client.query('SELECT indexname,indexdef FROM pg_indexes WHERE schemaname=$1 AND tablename=$2',['public',table.name])).rows;
   for(const original of table.indexes){
    const signature=index=>(index.indexdef.startsWith('CREATE UNIQUE')?'unique:':'index:')+index.indexdef.slice(index.indexdef.indexOf(' ON '));
    const matches=freshIndexes.filter(index=>signature(index)===signature(original));
    if(matches.length!==1)throw Error('Cannot identify fresh ticket index');
    if(matches[0].indexname!==original.indexname)await client.query(`ALTER INDEX public.${q(matches[0].indexname)} RENAME TO ${q(original.indexname)}`);
   }
   for(const column of table.columns.filter(c=>c.sequence&&!c.identity)){
    // The owned historical sequence moved with its table. New audit rows must
    // not consume that historical sequence or depend on the private schema.
    const sequence=table.name+'_'+column.name+'_seq';
    await client.query(`CREATE SEQUENCE public.${q(sequence)} AS bigint OWNED BY public.${q(table.name)}.${q(column.name)}`);
    await client.query(`ALTER TABLE public.${q(table.name)} ALTER COLUMN ${q(column.name)} SET DEFAULT nextval('public.${q(sequence)}'::regclass)`);
    await preserveGrants(client,'public.'+q(sequence),column.grants,'S');
   }
   // LIKE does not copy ACLs; also remove any extra default grants before restoring them.
   await preserveGrants(client,'public.'+q(table.name),table.grants);
   if((await client.query(`SELECT count(*)::text count FROM public.${q(table.name)}`)).rows[0].count!=='0')throw Error('Fresh ticket table is not empty');
   if((await client.query('SELECT $1::regclass::oid::text oid',[ticketHistorySchema+'.'+table.name])).rows[0].oid!==table.oid)throw Error('Historical table identity changed');
  }
  if(await configurationFingerprint(client)!==plan.configurationHash)throw Error('Customer configuration changed during ticket retirement');
  await client.query('COMMIT');open=false;
  return {archiveSchema:ticketHistorySchema,retired:plan.tables.map(({name,count})=>({name,count})),configurationPreserved:true,providerCalls:0};
 }finally{if(open)await client.query('ROLLBACK').catch(()=>{});}
}
