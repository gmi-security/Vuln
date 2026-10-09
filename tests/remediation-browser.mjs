// Browser workflow over the real built UI with synthetic, intercepted API data.
// Supply PLAYWRIGHT_MODULE as an installed Playwright index.mjs, or install it
// separately for testing. This does not add a production dependency.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { encode } from 'next-auth/jwt';

for(const file of ['.env','.env.local','.env.production','.env.production.local'])assert.equal(existsSync(file),false,'Use a checkout without app configuration');
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');
const reserve=createServer().listen(0,'127.0.0.1');await once(reserve,'listening');const port=reserve.address().port;await new Promise(r=>reserve.close(r));
const base=`http://127.0.0.1:${port}`,secret=randomBytes(32).toString('hex');
const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>/^(PATH|PATHEXT|SYSTEMROOT|WINDIR|TEMP|TMP|COMSPEC|USERPROFILE|APPDATA|LOCALAPPDATA)$/i.test(key)));
Object.assign(env,{NODE_ENV:'production',NEXTAUTH_URL:base,NEXTAUTH_SECRET:secret,VULN_DISABLE_SCHEDULER:'true',ELASTIC_VULN_ENABLED:'true',VULN_REMEDIATION_UI:'true'});
const server=spawn(process.execPath,['node_modules/next/dist/bin/next','start','-H','127.0.0.1','-p',String(port)],{env,windowsHide:true,stdio:['ignore','pipe','pipe']});
let serverOutput='';server.stdout.on('data',v=>serverOutput+=v);server.stderr.on('data',v=>serverOutput+=v);
let browser;
const artifacts=await mkdtemp(join(tmpdir(),'vuln2-browser-'));
const cve='CVE-2026-1234',when='2026-10-09T12:00:00Z',id='00000000-0000-4000-8000-000000000001';
const companies=[{id:'CO-TEST-A',name:'Fixture A'},{id:'CO-TEST-B',name:'Fixture B'}];
const summary=(companyId)=>({id,cves:[cve],hostCount:2,findingCount:2,remediationTitle:'Install recommended patch',companyName:companyId===companies[0].id?'Fixture A':'Fixture B',source:'stored-findings',state:'prepared',reviewState:'pending',preparedAt:when,updatedAt:when,worstSeverity:'High',maxRisk:72,closed:false,attachmentState:'not_started',slaEscalations:0,createdBy:null});
const group=(companyId)=>({manualOnly:true,source:'stored-findings',appCompanyId:companyId,companyName:companyId===companies[0].id?'Fixture A':'Fixture B',connectors:['defender'],title:'Install recommended patch',action:'Install recommended update',tenantId:companyId,remediationId:'manual:fixture',cves:[cve],deviceCount:2,findingCount:2,hostScope:[],deviceCves:[],maxRisk:72,worstSeverity:'High',label:cve,csv:`cve,hostname,cvss,remediation\r\n${cve},${companyId}-device,8.1,Install recommended update\r\n`,ticketTitle:`${companyId}: ${cve}`,ticketBody:`Customer: ${companyId}\nCVE: ${cve}\nRecommended remediation: Install recommended update\nCVSS: 8.1\nSee attached CSV for devices.`});
const detail=companyId=>({companyId,cve,companyName:companyId===companies[0].id?'Fixture A':'Fixture B',observedAt:when,sourceObservations:{platform:when,crowdstrike:null},findingCount:2,deviceCount:2,hosts:[{host:`${companyId}-device`,source:'defender',severity:'High',cvss:8.1}],enrichment:{cvss_score:8.1,epss_probability:0.9,cisa_kev:true,active_exploitation:true,active_exploitation_source:'MISP',active_exploitation_detail:'Synthetic retained signal',updated_at:when},tickets:[],moreTickets:false});
let approved=false,created=false,failPrepare=false,failIntel=false,delayDetail=false,releaseDetail;
const calls=[],unexpected=[],errors=[];let checks=0;
function pass(message){checks++;console.log('PASS '+message);}
try{
  let ready=false;
  for(let i=0;i<100;i++){try{if((await fetch(base+'/login')).ok){ready=true;break;}}catch{}await delay(100);}
  assert.ok(ready,serverOutput);
  browser=await chromium.launch({headless:true});
  const context=await browser.newContext({viewport:{width:1440,height:1000},acceptDownloads:true});
  const token=await encode({secret,token:{name:'Fixture member',orgMember:true,orgRole:'MEMBER'},maxAge:300});
  await context.addCookies([{name:'next-auth.session-token',value:token,url:base}]);
  const page=await context.newPage();page.setDefaultTimeout(10000);page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/*',async route=>{
    const req=route.request(),url=new URL(req.url());
    if(url.origin!==base){await route.abort();return;}
    if(!url.pathname.startsWith('/api/')){await route.continue();return;}
    const p=url.pathname.replace('/api/elastic-dashboard/',''),companyId=url.searchParams.get('companyId')||companies[0].id;
    const body=req.method()==='POST'?req.postDataJSON():null;calls.push({path:p,companyId:url.searchParams.get('companyId'),method:req.method(),body});
    const json=(data,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(data)});
    if(p==='/api/auth/session')return json({user:{name:'Fixture member'},expires:'2099-01-01T00:00:00Z'});
    if(p==='/api/settings')return json({settings:{sla:null}});
    if(p==='/api/elastic-vulnerabilities/status')return json({enabled:true,remediationEnabled:true});
    if(p==='/api/defender/results')return json({configured:false});
    if(p==='reporting')return json(url.searchParams.has('companyId')?{report:{company:{id:companyId}},model:{company:{id:'empty-fixture'}}}:{companies});
    if(p==='customer-tiles')return json({canManage:true,storageReady:true,connected:true,crowdstrike:{connected:true},availableSources:{elastic:true,crowdstrike:true},queries:['table','bar'].map(display=>({id:display,title:`Fixture ${display}`,companyId,source:'crowdstrike',query:'fixture',display,chart:{category:'cve',value:'devices'},enabled:false,refreshMinutes:1440,refreshedAt:when,attemptedAt:when,error:null,result:{columns:[{name:'cve',type:'keyword'},{name:'devices',type:'long'}],rows:[[cve,2]],truncated:false}}))});
    if(p==='patch-group-tickets')return json({requests:[summary(companyId)],more:false,total:1});
    if(p==='risk/summary')return json({totalOpenRisk:1,criticalRiskCount:0,swath1Open:0,swath2Open:1,kevOpen:1,internetFacingCriticalRisk:0,verifiedRemediations:0,awaitingVerification:0});
    if(p==='risk/top')return json({rows:[{id:'risk-1',cve,companyId,hostname:'fixture-host',severity:'High',riskScore:720,effectiveSwath:2,calculatedSwath:2,reasons:[],cisaKev:true,epssProbability:0.9,verificationStatus:'detected',lastSeen:when}],total:1});
    if(p==='customer-threat-intelligence')return failIntel?json({error:'Fixture refresh unavailable'},503):json({companyId,available:true,total:1,rows:[{cve,cisa_kev:true,epss_probability:0.9,active_exploitation:true,active_exploitation_source:'MISP',active_exploitation_detail:'Synthetic retained signal',updated_at:when}]});
    if(p==='customer-cve'){
      if(req.method()==='GET'){
        if(delayDetail && companyId===companies[0].id){delayDetail=false;await new Promise(r=>releaseDetail=r);}
        return json(detail(companyId));
      }
      if(failPrepare)return json({error:'Fixture missing remediation; no partial request was saved.'},409);
      return json({companyId:body.companyId,cve,observedAt:when,groups:[{id,group:group(body.companyId)}]});
    }
    if(p==='connectwise')return json({configured:true,revision:1,defaults:{boardId:9}});
    if(p==='connectwise/options')return json({options:url.searchParams.get('kind')==='companies'?[{id:55,name:'Fixture ConnectWise company'}]:url.searchParams.get('kind')==='boards'?[{id:9,name:'Fixture Patch Board'}]:[],more:false,page:1,revision:1});
    if(p===`patch-group-tickets/${id}`){
      if(body?.action==='approve')approved=true;
      if(body?.action==='create'){assert.ok(approved);created=true;}
      return json({request:{...summary(companyId),reviewState:approved?'approved':'pending',state:created?'created':'prepared',ticketId:created?999:null,attachmentState:created?'attached':'not_started',ticketStatus:created?'New':null}});
    }
    unexpected.push(p);return json({error:'Unexpected fixture request'},500);
  });
  await page.goto(base+`/remediation?companyId=${companies[0].id}&view=overview`);
  const tile=page.getByRole('region',{name:'Fixture table',exact:true});
  const opener=tile.getByRole('button',{name:`View ${cve} details`});await opener.click();
  const panel=page.getByRole('dialog',{name:cve,exact:true});await panel.getByText(`${companies[0].id}-device`,{exact:true}).waitFor();
  assert.equal(await panel.getByRole('button',{name:'Close',exact:true}).evaluate(e=>e===document.activeElement),true);
  await page.keyboard.press('Escape');await panel.waitFor({state:'hidden'});
  assert.equal(await opener.evaluate(e=>e===document.activeElement),true);
  pass('table CVE opens shared panel; Escape closes and restores keyboard focus');

  await page.getByRole('region',{name:'Fixture bar',exact:true}).getByRole('button',{name:new RegExp(cve)}).first().click();
  await panel.getByRole('button',{name:'Prepare patch request',exact:true}).waitFor();
  failPrepare=true;await panel.getByRole('button',{name:'Prepare patch request',exact:true}).click();await panel.getByRole('alert').waitFor();
  assert.equal(await panel.getByRole('button',{name:'Download host CSV'}).count(),0);
  failPrepare=false;await panel.getByRole('button',{name:'Prepare patch request',exact:true}).click();
  await panel.getByRole('button',{name:'Download host CSV'}).waitFor();
  assert.equal(calls.filter(c=>c.body?.action==='create').length,0);
  const downloadPromise=page.waitForEvent('download');await panel.getByRole('button',{name:'Download host CSV'}).click();
  const download=await downloadPromise;let csv='';for await(const chunk of await download.createReadStream())csv+=chunk;
  assert.match(csv,/CO-TEST-A-device/);assert.doesNotMatch(csv,/CO-TEST-B/);
  await panel.getByText('Ticket contents',{exact:true}).click();assert.doesNotMatch(await panel.locator('pre').innerText(),/CO-TEST-A-device/);
  await panel.getByRole('button',{name:'Approve draft for manual sending'}).click();await panel.getByRole('button',{name:'Review ConnectWise ticket'}).click();
  await panel.getByLabel('ConnectWise company',{exact:true}).selectOption('55');await panel.getByLabel('Service board',{exact:true}).selectOption('9');
  await panel.getByRole('button',{name:'Create ConnectWise ticket',exact:true}).click();await panel.getByText(/#999/).first().waitFor();
  const sent=calls.find(c=>c.body?.action==='create');assert.equal(sent.companyId,companies[0].id);assert.equal(sent.body.routing.companyId,55);assert.equal(sent.body.routing.boardId,9);
  assert.ok(calls.filter(c=>c.path===`patch-group-tickets/${id}`).every(c=>c.companyId===companies[0].id));
  await panel.evaluate(e=>{e.scrollTop=0;window.scrollTo(0,0);});
  await page.screenshot({path:join(artifacts,'shared-cve-fixture.png')});
  pass('chart CVE uses the same panel; failed preparation saves no partial UI; CSV, approval and simulated ticket send remain scoped');

  await page.keyboard.press('Escape');await page.getByRole('button',{name:'Prioritize',exact:true}).click();
  const intel=page.getByRole('region',{name:'Threat Intelligence'});await intel.getByRole('button',{name:`View ${cve} details`}).click();await panel.getByText(`${companies[0].id}-device`,{exact:true}).waitFor();await page.keyboard.press('Escape');
  failIntel=true;await intel.getByRole('button',{name:'Refresh saved evidence'}).click();await intel.getByRole('alert').waitFor({timeout:15000});assert.match(await intel.innerText(),/Synthetic retained signal/);
  await page.getByRole('link',{name:'Review & approve in ticket queue'}).first().click();
  await page.waitForURL(/view=tickets/);await page.getByRole('button',{name:`View ${cve} details`}).first().click();await panel.getByText(`${companies[0].id}-device`,{exact:true}).waitFor();await page.keyboard.press('Escape');
  pass('Prioritize threat and Tickets CVE links share the flow; failed enrichment refresh keeps its last result');

  delayDetail=true;await page.getByRole('button',{name:`View ${cve} details`}).first().click();await panel.getByText('Loading saved customer evidence…').waitFor();
  await page.keyboard.press('Escape');await page.getByRole('region',{name:'Customer report',exact:true}).getByRole('combobox').selectOption(companies[1].id);
  await page.getByRole('button',{name:`View ${cve} details`}).first().click();await panel.getByText(`${companies[1].id}-device`,{exact:true}).waitFor();
  releaseDetail();await delay(150);assert.doesNotMatch(await panel.innerText(),/CO-TEST-A-device/);
  await page.setViewportSize({width:390,height:844});const box=await panel.boundingBox();assert.ok(box.width<=390 && box.x>=0);
  await page.keyboard.press('Tab');assert.equal(await panel.evaluate(e=>e.contains(document.activeElement)),true);
  await page.screenshot({path:join(artifacts,'shared-cve-mobile-fixture.png')});
  pass('late previous-customer response is ignored; mobile panel fits and keeps keyboard focus');
  assert.deepEqual(unexpected,[]);assert.deepEqual(errors,[]);
  await writeFile(join(artifacts,'result.json'),JSON.stringify({checks,passed:true,syntheticData:true,realTicketsSent:0,unexpected,errors},null,2));
  console.log(JSON.stringify({checks,passed:true,artifacts,realTicketsSent:0}));
}catch(error){
  const page=browser?.contexts()[0]?.pages()[0];
  if(page)await page.screenshot({path:join(artifacts,'failure.png'),fullPage:true}).catch(()=>{});
  await writeFile(join(artifacts,'failure.json'),JSON.stringify({error:String(error),unexpected,errors,calls},null,2));
  console.error('Browser failure artifacts: '+artifacts);
  throw error;
}finally{
  if(browser)await browser.close();
  const stopped=once(server,'exit');server.kill();await stopped;
}
