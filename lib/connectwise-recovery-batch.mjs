import {createHash} from 'node:crypto';
import {readdir,readFile,lstat,open} from 'node:fs/promises';
import path from 'node:path';
import {request as httpsRequest} from 'node:https';

const sha256=value=>createHash('sha256').update(value).digest('hex');
const fail=code=>{throw Error(code);};
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const digest=/^[a-f0-9]{64}$/;
const scope={companyId:32628,boardId:159,appCompanyId:'CO-147284'};
const first=14,last=71,minimumGapMs=120_000,maxResponseBytes=2_097_152;
const pinnedNames=['checkpoint.json','single-12-result.json','single-13-started.json',
  'single-13-retry-01-started.json','single-13-retry-01-result.json'];

async function regularFile(file){
  const stat=await lstat(file).catch(()=>fail('EVIDENCE_MISSING'));
  if(!stat.isFile()||stat.isSymbolicLink())fail('INVALID_EVIDENCE_FILE');
  return readFile(file);
}

async function pinnedJson(dir,name,expected){
  if(!digest.test(expected??''))fail('EVIDENCE_PIN_MISSING');
  const raw=await regularFile(path.join(dir,name));
  if(sha256(raw)!==expected)fail(name==='checkpoint.json'?'CHECKPOINT_CHANGED':'EVIDENCE_CHANGED');
  try{return JSON.parse(raw.toString('utf8'));}catch{fail('INVALID_EVIDENCE_JSON');}
}

async function generatedJson(dir,name){
  const raw=await regularFile(path.join(dir,name));
  const saved=(await regularFile(path.join(dir,`${name}.sha256`))).toString('utf8').trim();
  if(!digest.test(saved)||sha256(raw)!==saved)fail('EVIDENCE_CHANGED');
  try{return {value:JSON.parse(raw.toString('utf8')),sha256:saved};}catch{fail('INVALID_EVIDENCE_JSON');}
}

// Exclusive, synced files make a crash after an attempt visible to the next preflight.
export async function exclusiveWrite(name,value,dir){
  const raw=Buffer.from(JSON.stringify(value,null,2)+'\n');
  const file=path.join(dir,name),sidecar=path.join(dir,`${name}.sha256`);
  for(const [target,data] of [[file,raw],[sidecar,Buffer.from(`${sha256(raw)}\n`)]] ){
    const handle=await open(target,'wx',0o600);
    try{await handle.writeFile(data);await handle.sync();}finally{await handle.close();}
  }
  if(process.platform!=='win32'){
    const handle=await open(dir,'r');
    try{await handle.sync();}finally{await handle.close();}
  }
  return sha256(raw);
}

export function classifyLookup(status,body,row){
  if(status===429)return {classification:'rate_limited'};
  if(status!==200)return {classification:'http_error'};
  let tickets;
  try{tickets=JSON.parse(body);}catch{return {classification:'invalid_response'};}
  if(!Array.isArray(tickets))return {classification:'invalid_response'};
  if(tickets.length===0)return {classification:'not_found',responseCount:0};
  if(tickets.length!==1)return {classification:'ambiguous',responseCount:tickets.length};
  const ticket=tickets[0];
  if(!ticket||typeof ticket!=='object'||Array.isArray(ticket))return {classification:'invalid_response',responseCount:1};
  const ticketId=Number.isSafeInteger(ticket.id)&&ticket.id>0?ticket.id:null;
  const referenceMatches=ticket.externalXRef===`GMI-GRP-${row.requestId}`;
  const companyMatches=ticket.company?.id===row.companyId;
  const boardMatches=ticket.board?.id===row.boardId;
  return {classification:ticketId&&referenceMatches&&companyMatches&&boardMatches?'found_verified':'mismatch',
    responseCount:1,ticketId,referenceMatches,companyMatches,boardMatches};
}

function validResult(result,requestId){
  if(result?.requestId!==requestId||result.method!=='GET'||result.httpStatus!==200||
     !digest.test(result.responseSha256??'')||!Number.isFinite(Date.parse(result.checkedAt)))return false;
  if(result.classification==='not_found')return result.responseCount===0;
  return result.classification==='found_verified'&&result.responseCount===1&&
    Number.isSafeInteger(result.ticketId)&&result.ticketId>0&&
    result.referenceMatches===true&&result.companyMatches===true&&result.boardMatches===true;
}

function validateCheckpoint(checkpoint){
  const pending=checkpoint?.pending;
  if(checkpoint?.cohortSize!==96||!Array.isArray(pending)||pending.length!==72||
    new Set(pending.map(p=>p?.requestId)).size!==72||
    pending.some(p=>!uuid.test(p?.requestId??'')||!digest.test(p?.scopeHash??'')||typeof p.reason!=='string')||
    pending.slice(13).some(p=>p.reason!=='not_queried'))fail('CHECKPOINT_INVALID');
  return pending;
}

function validateDatabase(database,pending){
  if(database?.database!=='recovery_merge_fenced'||database.readOnly!==true)fail('DATABASE_NOT_READ_ONLY');
  if(database.cohortCount!==96)fail('SCOPE_MISMATCH');
  const connection=database.connection;
  let endpoint;
  try{endpoint=new URL(connection?.endpoint);}catch{fail('CONNECTION_INVALID');}
  if(endpoint.protocol!=='https:'||endpoint.username||endpoint.password||endpoint.search||endpoint.hash||
     (endpoint.port&&endpoint.port!=='443')||!/^\/v[a-z0-9_.-]+\/apis\/3\.0$/i.test(endpoint.pathname)||
     !['companyId','clientId','publicKey','privateKey'].every(key=>typeof connection[key]==='string'&&connection[key])||
     connection.target!==sha256(`${endpoint.host.toLowerCase()}/${connection.companyId.toLowerCase()}`))fail('TARGET_MISMATCH');
  const rows=database.rows;
  if(!Array.isArray(rows)||rows.length!==last-13+1||new Set(rows.map(r=>r.requestId)).size!==rows.length)fail('SCOPE_MISMATCH');
  const byId=new Map(rows.map(r=>[r.requestId,r]));
  for(let index=13;index<=last;index++){
    const request=pending[index],row=byId.get(request.requestId);
    if(!row||row.scopeHash!==request.scopeHash||row.state!=='uncertain'||row.ticketId!==null||
       row.companyId!==scope.companyId||row.boardId!==scope.boardId||row.appCompanyId!==scope.appCompanyId||
       row.cwTarget!==connection.target)fail('SCOPE_MISMATCH');
  }
  return byId;
}

export async function preflightRecovery({dir,pins,readDb}){
  const stat=await lstat(dir).catch(()=>fail('EVIDENCE_DIRECTORY_MISSING'));
  if(!stat.isDirectory()||stat.isSymbolicLink()||(process.platform!=='win32'&&(stat.mode&0o077)!==0))
    fail('EVIDENCE_DIRECTORY_UNSAFE');
  for(const name of pinnedNames)if(!pins?.[name])fail('EVIDENCE_PIN_MISSING');
  const checkpoint=await pinnedJson(dir,'checkpoint.json',pins['checkpoint.json']);
  const pending=validateCheckpoint(checkpoint);
  const prior=await pinnedJson(dir,'single-12-result.json',pins['single-12-result.json']);
  const original=await pinnedJson(dir,'single-13-started.json',pins['single-13-started.json']);
  const retryStart=await pinnedJson(dir,'single-13-retry-01-started.json',pins['single-13-retry-01-started.json']);
  const retry=await pinnedJson(dir,'single-13-retry-01-result.json',pins['single-13-retry-01-result.json']);
  if(prior?.requestId!==pending[12].requestId||prior.method!=='GET'||
     original?.requestId!==pending[13].requestId||original.method!=='GET'||
     retryStart?.requestId!==pending[13].requestId||retryStart.method!=='GET'||retryStart.attempt!==2||
     !Number.isFinite(Date.parse(retryStart.startedAt))||retry?.attempt!==2||
     !validResult(retry,pending[13].requestId)||retry.classification!=='found_verified'||
     Date.parse(retry.checkedAt)<Date.parse(retryStart.startedAt))fail('INDEX_13_RETRY_INVALID');
  const names=new Set(await readdir(dir));
  if(names.has('single-13-result.json')||names.has('single-13-retry-01-failure.json'))fail('INDEX_13_RETRY_INVALID');
  for(const name of names){
    const match=/^single-(\d+)-/.exec(name);
    if(!match||Number(match[1])<first)continue;
    const index=Number(match[1]);
    const allowed=index<=last&&['started.json','result.json','failure.json'].flatMap(s=>
      [`single-${index}-${s}`,`single-${index}-${s}.sha256`]).includes(name);
    if(!allowed)fail('UNEXPECTED_EVIDENCE');
  }
  let nextIndex=first,lastCheckedAt=retry.checkedAt,previousResultSha256=pins['single-13-retry-01-result.json'];
  const completed=[];
  for(let index=first;index<=last;index++){
    const start=`single-${index}-started.json`,result=`single-${index}-result.json`,failure=`single-${index}-failure.json`;
    const present=[start,result,failure].some(name=>names.has(name)||names.has(`${name}.sha256`));
    if(!present)continue;
    if(index!==nextIndex)fail('NONCONTIGUOUS_EVIDENCE');
    if(names.has(failure)||!names.has(start)||!names.has(result)||!names.has(`${start}.sha256`)||
       !names.has(`${result}.sha256`))fail('INCOMPLETE_ATTEMPT');
    const marker=await generatedJson(dir,start),outcome=await generatedJson(dir,result);
    if(marker.value.requestId!==pending[index].requestId||marker.value.method!=='GET'||marker.value.index!==index||
       marker.value.scopeHash!==pending[index].scopeHash||marker.value.checkpointSha256!==pins['checkpoint.json']||
       marker.value.previousResultSha256!==previousResultSha256||marker.value.attempt!==1||
       !Number.isFinite(Date.parse(marker.value.startedAt))||
       Date.parse(marker.value.startedAt)-Date.parse(lastCheckedAt)<minimumGapMs||
       !validResult(outcome.value,pending[index].requestId)||outcome.value.index!==index||
       Date.parse(outcome.value.checkedAt)<Date.parse(marker.value.startedAt))fail('INVALID_EVIDENCE');
    completed.push({index,requestId:pending[index].requestId,classification:outcome.value.classification,
      ticketId:outcome.value.ticketId??null,resultSha256:outcome.sha256});
    previousResultSha256=outcome.sha256;lastCheckedAt=outcome.value.checkedAt;nextIndex++;
  }
  const database=await readDb(pending.slice(13).map(p=>p.requestId));
  const rows=validateDatabase(database,pending);
  const reportName='batch-14-71-report.json';
  if(names.has(reportName)||names.has(`${reportName}.sha256`)){
    if(nextIndex!==last+1)fail('INVALID_EVIDENCE');
    const existing=await generatedJson(dir,reportName);
    if(JSON.stringify(existing.value)!==JSON.stringify(reportFor({checkpointSha256:pins['checkpoint.json'],completed})))
      fail('REPORT_MISMATCH');
  }
  return {nextIndex,remaining:last-nextIndex+1,pending,rows,connection:database.connection,
    checkpointSha256:pins['checkpoint.json'],previousResultSha256,lastCheckedAt,completed};
}

export async function boundedGet({url,ip,headers,limit=maxResponseBytes,timeoutMs=15_000,requestImpl}){
  const invoke=requestImpl??(()=>new Promise((resolve,reject)=>{
    const req=httpsRequest(url,{method:'GET',agent:false,family:4,autoSelectFamily:false,
      lookup:(_host,options,cb)=>options.all?cb(null,[{address:ip,family:4}]):cb(null,ip,4),headers},res=>{
      const chunks=[];let size=0;
      res.on('data',chunk=>{size+=chunk.length;if(size>limit)req.destroy(Error('RESPONSE_TOO_LARGE'));else chunks.push(chunk);});
      res.on('error',reject);
      res.on('aborted',()=>reject(Error('RESPONSE_ABORTED')));
      res.on('close',()=>{if(!res.complete)reject(Error('RESPONSE_INCOMPLETE'));});
      res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString('utf8')}));
    });
    const timer=setTimeout(()=>req.destroy(Error('GET_TIMEOUT')),timeoutMs);
    req.on('close',()=>clearTimeout(timer));
    req.on('error',reject);req.end();
  }));
  const response=await invoke();
  if(!Number.isInteger(response?.status)||typeof response.body!=='string'||
    Buffer.byteLength(response.body)>limit)fail('RESPONSE_TOO_LARGE');
  return response;
}

function reportFor(plan){
  const found=plan.completed.filter(x=>x.classification==='found_verified').length;
  const notFound=plan.completed.filter(x=>x.classification==='not_found').length;
  return {checkpointSha256:plan.checkpointSha256,cohortSize:96,previouslyVerified:34,
    previouslyUnresolved:4,processed:58,foundVerified:found,notFoundUnresolved:notFound,
    totalVerified:34+found,totalUnresolved:4+notFound,records:plan.completed};
}

async function finalReport(plan,dir,writeEvidence){
  if(plan.remaining!==0)fail('INCOMPLETE_BATCH');
  const report=reportFor(plan);
  const names=new Set(await readdir(dir)),name='batch-14-71-report.json';
  if(names.has(name)||names.has(`${name}.sha256`)){
    const existing=await generatedJson(dir,name);
    if(JSON.stringify(existing.value)!==JSON.stringify(report))fail('REPORT_MISMATCH');
  }else await writeEvidence(name,report,dir).catch(()=>fail('EVIDENCE_WRITE_FAILED'));
  return report;
}

export async function executeRecovery({dir,pins,readDb,sendGet,now=()=>new Date(),sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),
  writeEvidence=exclusiveWrite,maxRequests=Infinity}){
  let plan=await preflightRecovery({dir,pins,readDb});
  if(plan.remaining===0)return finalReport(plan,dir,writeEvidence);
  let processed=0;
  for(let index=plan.nextIndex;index<=last;index++){
    if(processed>=maxRequests)fail('BATCH_PAUSED');
    plan=await preflightRecovery({dir,pins,readDb});
    if(plan.nextIndex!==index)fail('EVIDENCE_CHANGED');
    const wait=minimumGapMs-(now().getTime()-Date.parse(plan.lastCheckedAt));
    if(!Number.isFinite(wait)||wait>minimumGapMs)fail('TIMESTAMP_INVALID');
    if(wait>0)await sleep(wait);
    if(now().getTime()-Date.parse(plan.lastCheckedAt)<minimumGapMs)fail('COOLDOWN_ACTIVE');
    const request=plan.pending[index],row=plan.rows.get(request.requestId);
    const marker={requestId:request.requestId,method:'GET',attempt:1,index,scopeHash:request.scopeHash,
      checkpointSha256:plan.checkpointSha256,previousResultSha256:plan.previousResultSha256,
      startedAt:now().toISOString()};
    await writeEvidence(`single-${index}-started.json`,marker,dir);
    let response;
    try{response=await sendGet({requestId:request.requestId,row,connection:plan.connection});}
    catch(error){
      const category=/^[A-Z][A-Z0-9_]{1,63}$/.test(error?.code??'')?error.code:
        ['GET_TIMEOUT','RESPONSE_TOO_LARGE','RESPONSE_ABORTED','RESPONSE_INCOMPLETE'].includes(error?.message)?error.message:'UNCLASSIFIED_ERROR';
      await writeEvidence(`single-${index}-failure.json`,{requestId:request.requestId,method:'GET',index,
        checkedAt:now().toISOString(),errorCategory:category},dir).catch(()=>fail('EVIDENCE_WRITE_FAILED'));
      fail('LOOKUP_STOPPED');
    }
    if(!Number.isInteger(response?.status)||typeof response.body!=='string'||
       Buffer.byteLength(response.body)>maxResponseBytes)fail('EVIDENCE_WRITE_FAILED');
    const classified=classifyLookup(response.status,response.body,row);
    const result={requestId:request.requestId,method:'GET',attempt:1,index,checkedAt:now().toISOString(),
      httpStatus:response.status,responseSha256:sha256(response.body),...classified};
    const retryAfter=response.headers?.['retry-after'];
    if(typeof retryAfter==='string'&&retryAfter.length<=100&&
       (/^\d+$/.test(retryAfter)||Number.isFinite(Date.parse(retryAfter))))result.retryAfter=retryAfter;
    await writeEvidence(`single-${index}-result.json`,result,dir).catch(()=>fail('EVIDENCE_WRITE_FAILED'));
    processed++;
    if(!['found_verified','not_found'].includes(result.classification))fail('LOOKUP_STOPPED');
  }
  plan=await preflightRecovery({dir,pins,readDb});
  return finalReport(plan,dir,writeEvidence);
}
