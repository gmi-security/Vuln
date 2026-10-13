// Offline preflight by default. --execute is the only path that sends GETs.
import {createDecipheriv,createHash,hkdfSync} from 'node:crypto';
import {lookup as dnsLookup} from 'node:dns/promises';
import {readFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseEnv} from 'node:util';
import pg from 'pg';
import {preflightRecovery,executeRecovery,boundedGet} from '../lib/connectwise-recovery-batch.mjs';

const dir='/home/codex/vuln-recovery/cw-get-resume-zm1i62th';
const socket='/home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket';
const pins={
  'checkpoint.json':'436ffc6eff38a8d82e16128a36831e4781e55db7ae915a3be400bbf44a3d40e9',
  'single-12-result.json':'c71daa78bb4b253242510afa7851fe86479aca77f7b349f2fafe87358bbd4473',
  'single-13-started.json':'d0a3457302e400d6d62855e2742d6fd7770c364f1aca8dbb6d59feaecb08fe38',
  'single-13-retry-01-started.json':'3f7d9051382fc0a2bb57a4446491135822f98531d5bc80e599b59321b52d6d1d',
  'single-13-retry-01-result.json':'a095869f15911a6ca7dd5cb6f561f1e57ecdcc75e26c8405bb9efa661aa28200',
};
const sha256=value=>createHash('sha256').update(value).digest('hex');
const fail=code=>{throw Error(code);};

function decryptConnection(secret,saved){
  try{
    if(typeof secret!=='string'||secret.length<32||typeof saved!=='string')fail('INVALID_CONNECTION');
    const [version,iv,tag,data,...rest]=saved.split('.');
    if(version!=='v1'||!iv||!tag||!data||rest.length)fail('INVALID_CONNECTION');
    const key=Buffer.from(hkdfSync('sha256',secret,'gmi-vuln','connectwise-connection-v1',32));
    const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(iv,'base64'));
    decipher.setAuthTag(Buffer.from(tag,'base64'));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(data,'base64')),decipher.final()]).toString('utf8'));
  }catch{fail('CONNECTION_DECRYPT_FAILED');}
}

export async function readRecoveryDatabase(requestIds,{clientFactory=cfg=>new pg.Client(cfg),
  readSecret=async()=>parseEnv(await readFile('/opt/vuln/.env.local','utf8')).NEXTAUTH_SECRET}={}){
  if(!Array.isArray(requestIds)||requestIds.length!==59||
     requestIds.some(id=>!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id)))fail('INVALID_REQUEST_IDS');
  const client=clientFactory({host:socket,port:55483,user:'codex',database:'recovery_merge_fenced',
    connectionTimeoutMillis:8000,options:'-c default_transaction_read_only=on -c statement_timeout=15000'});
  await client.connect();
  try{
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity=(await client.query("SELECT current_database() AS database, current_setting('transaction_read_only')='on' AS \"readOnly\"")).rows[0];
    if(identity?.database!=='recovery_merge_fenced'||identity.readOnly!==true)fail('DATABASE_NOT_READ_ONLY');
    const rows=(await client.query(`SELECT id::text AS "requestId",scope_hash AS "scopeHash",state,
      ticket_id AS "ticketId",cw_target AS "cwTarget",company_id AS "companyId",
      (routing->>'boardId')::integer AS "boardId",packet->>'appCompanyId' AS "appCompanyId"
      FROM patch_group_ticket_requests WHERE id=ANY($1::uuid[])`,[requestIds])).rows;
    const cohortCount=(await client.query("SELECT count(*)::integer AS count FROM patch_group_ticket_requests WHERE state='uncertain'")).rows[0]?.count;
    const saved=(await client.query('SELECT secret,target FROM patch_connectwise_connection WHERE id=1')).rows;
    if(saved.length!==1||typeof saved[0].target!=='string')fail('CONNECTION_INVALID');
    const connection={...decryptConnection(await readSecret(),saved[0].secret),target:saved[0].target};
    return {database:identity.database,readOnly:identity.readOnly,cohortCount,rows,connection};
  }finally{
    await client.query('ROLLBACK').catch(()=>{});
    await client.end();
  }
}

function publicIPv4(ip){
  if(isIP(ip)!==4)return false;
  const [a,b,c]=ip.split('.').map(Number);
  return !(a===0||a===10||a===127||a>=224||
    (a===100&&b>=64&&b<=127)||(a===169&&b===254)||
    (a===172&&b>=16&&b<=31)||
    (a===192&&(b===168||b===0||b===2||(b===88&&c===99)))||
    (a===198&&(b===18||b===19||(b===51&&c===100)))||
    (a===203&&b===0&&c===113));
}

export async function sendConnectWiseGet({requestId,row,connection},{lookup=dnsLookup,get=boundedGet,dnsTimeoutMs=5000}={}){
  if(requestId!==row?.requestId||!/^[-a-f0-9]{36}$/.test(requestId))fail('REQUEST_ID_MISMATCH');
  let endpoint;
  try{endpoint=new URL(connection.endpoint);}catch{fail('ENDPOINT_INVALID');}
  if(endpoint.protocol!=='https:'||endpoint.username||endpoint.password||endpoint.search||endpoint.hash||
     (endpoint.port&&endpoint.port!=='443')||!/^\/v[a-z0-9_.-]+\/apis\/3\.0$/i.test(endpoint.pathname)||
     connection.target!==sha256(`${endpoint.host.toLowerCase()}/${connection.companyId.toLowerCase()}`))fail('ENDPOINT_INVALID');
  const url=new URL(`${endpoint.toString().replace(/\/$/,'')}/service/tickets`);
  url.search=new URLSearchParams({conditions:`externalXRef="GMI-GRP-${requestId}"`,pageSize:'2'}).toString();
  let dnsTimer;
  const ip=(await Promise.race([lookup(endpoint.hostname,{family:4}),
    new Promise((_,reject)=>{dnsTimer=setTimeout(()=>reject(Error('DNS_TIMEOUT')),dnsTimeoutMs);})
  ]).finally(()=>clearTimeout(dnsTimer))).address;
  if(!publicIPv4(ip))fail('NONPUBLIC_DNS');
  const headers={Authorization:`Basic ${Buffer.from(`${connection.companyId}+${connection.publicKey}:${connection.privateKey}`).toString('base64')}`,
    clientId:connection.clientId,Accept:'application/json'};
  return get({url,ip,headers});
}

async function main(){
  const args=process.argv.slice(2);
  if(args.length>1||(args[0]&&args[0]!=='--execute'))fail('Usage: node scripts/connectwise-recovery-batch.mjs [--execute]');
  process.umask(0o077);
  if(args[0]!=='--execute'){
    const plan=await preflightRecovery({dir,pins,readDb:readRecoveryDatabase});
    console.log(JSON.stringify({mode:'preflight',checkpointSha256:plan.checkpointSha256,
      nextIndex:plan.nextIndex,remaining:plan.remaining,lastCheckedAt:plan.lastCheckedAt,
      noExternalRequests:true,noDatabaseWrites:true},null,2));
    return;
  }
  const report=await executeRecovery({dir,pins,readDb:readRecoveryDatabase,sendGet:sendConnectWiseGet});
  console.log(JSON.stringify({mode:'execute',reportFile:`${dir}/batch-14-71-report.json`,
    processed:report.processed,totalVerified:report.totalVerified,totalUnresolved:report.totalUnresolved,
    noDatabaseWrites:true},null,2));
}

if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url)
  main().catch(error=>{console.error(error?.message??'RECOVERY_STOPPED');process.exitCode=1;});
