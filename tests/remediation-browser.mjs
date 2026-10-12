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
import {publishedComparisonFixture} from './shadow-platform-browser.mjs';

for(const file of ['.env','.env.local','.env.production','.env.production.local'])assert.equal(existsSync(file),false,'Use a checkout without app configuration');
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');
const reserve=createServer().listen(0,'127.0.0.1');await once(reserve,'listening');const port=reserve.address().port;await new Promise(r=>reserve.close(r));
const base=`http://127.0.0.1:${port}`,secret=randomBytes(32).toString('hex');
const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>/^(PATH|PATHEXT|SYSTEMROOT|WINDIR|TEMP|TMP|COMSPEC|USERPROFILE|APPDATA|LOCALAPPDATA)$/i.test(key)));
const savedReads=process.env.VULN_TEST_SAVED_SOURCES==='true';
const shadowReads=process.env.VULN_TEST_SHADOW_CVE==='true';
let comparisonState='available',delayComparison=false,releaseComparison;
Object.assign(env,{NODE_ENV:'production',NEXTAUTH_URL:base,NEXTAUTH_SECRET:secret,VULN_DISABLE_SCHEDULER:'true',ELASTIC_VULN_ENABLED:'true',VULN_REMEDIATION_UI:'true'});
if(savedReads)env.VULN_SAVED_SOURCE_READS='true';
if(shadowReads)env.VULN_SHADOW_CVE_READS='true';
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
let mismatchOverview=false,delayOverview=false,releaseOverview;
function overviewModel(companyId){
  const company=companies.find(c=>c.id===companyId),count=companyId===companies[0].id?1:2;
  return {company,metrics:{vulnerabilities:{open:count,critical:0,high:count,kev:0,exploitable:0,cveOpen:count,
    bySeverity:{Critical:0,High:count,Medium:0,Low:0,Info:0},assessed:true},attackSurface:{open:0},webTesting:{open:0,assessed:false}},
    assessmentState:'assessed',sourceActivity:[],priorityTotal:count,priorityRows:[{id:'overview-finding',cve,title:'Overview patch',
      asset:`${companyId}-overview-device`,severity:'High',realRisk:72,status:'Open',lastSeen:when,connectors:['defender']}],
    scanTotal:0,recentScans:[],assets:{inventoryCount:2,authoritativeFindingCount:0,contextCoveragePercent:0,scanCoveragePercent:null,sourceCounts:[]},
    attackSurfaceRows:[],webTestingRows:[],history:[]};
}
let sourceState='available',failSource=false,delaySource=false,releaseSource;
function savedResult(companyId,source,offset){
  const state=sourceState==='pending'?'summary-pending':'available';
  return {companyId,source,state,version:1,scope:'saved-source-generation',
    generation:state==='available'?{id:'fixture',completedAt:when,freshness:sourceState==='stale'?'stale':'within-window',revisionMatches:sourceState!=='stale'}:null,
    latestAttempt:sourceState==='stale'?{status:'failed'}:null,projection:sourceState==='stale'?{state:'pending'}:undefined,
    summary:state==='available'?{sourceInstances:1234,deviceCveFindings:1200,uniqueCves:51,affectedDevices:34,unknownSuppressionInstances:0,excludedNonCveInstances:0}:null,
    cves:state==='available'?{offset,limit:50,total:51,rows:[{cve:offset?'CVE-2026-9999':cve,severity:'HIGH',cvss:8.1,affectedDevices:34}]}:null};
}
const calls=[],unexpected=[],errors=[];let checks=0;
const published=publishedComparisonFixture({companies,cve,when,id,calls});
function pass(message){checks++;console.log('PASS '+message);}
try{
  let ready=false;
  for(const deadline=Date.now()+90000;Date.now()<deadline;){try{if((await fetch(base+'/login',{signal:AbortSignal.timeout(2000)})).ok){ready=true;break;}}catch{}await delay(100);}
  assert.ok(ready,serverOutput);
  browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
  const context=await browser.newContext({viewport:{width:1440,height:1000},acceptDownloads:true});
  const token=await encode({secret,token:{name:'Fixture member',orgMember:true,orgRole:'MEMBER'},maxAge:300});
  await context.addCookies([{name:'next-auth.session-token',value:token,url:base}]);
  const endpoint=base+'/api/elastic-dashboard/customer-cve-comparison?companyId=CO-TEST-A&cve=CVE-2026-1234';
  assert.equal((await fetch(endpoint)).status,401);
  const gated=await context.request.get(endpoint);assert.equal(gated.status(),shadowReads?409:404);
  assert.match(gated.headers()['cache-control'],/no-store/);
  assert.equal((await context.request.post(endpoint,{data:{}})).status(),405);
  const page=await context.newPage();page.setDefaultTimeout(10000);page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/*',async route=>{
    const req=route.request(),url=new URL(req.url());
    if(url.origin!==base){await route.abort();return;}
    if(!url.pathname.startsWith('/api/')){await route.continue();return;}
    const p=url.pathname.replace('/api/elastic-dashboard/',''),companyId=url.searchParams.get('companyId')||companies[0].id;
    const body=req.method()==='POST'?req.postDataJSON():null;calls.push({path:p,companyId:url.searchParams.get('companyId'),view:url.searchParams.get('view'),method:req.method(),body});
    const json=(data,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(data)});
    if(p==='preview'){
      assert.equal(body.companyId,companies[0].id);assert.equal(body.source,'crowdstrike');
      return json({jobId:id,status:'queued'});
    }
    if(p===`jobs/${id}`){
      return json({jobId:id,status:'succeeded',result:{columns:[{name:'cve',type:'keyword'},{name:'devices',type:'long'}],rows:[[cve,2]],truncated:false}});
    }
    if(p==='customer-platform-comparison')return published.handle({req,url,json});
    if(p==='/api/auth/session')return json({user:{name:'Fixture member'},expires:'2099-01-01T00:00:00Z'});
    if(p==='/api/settings')return json({settings:{sla:null}});
    if(p==='/api/elastic-vulnerabilities/status')return json({enabled:true,remediationEnabled:true});
    if(p==='/api/defender/results')return json({configured:false});
    if(p==='reporting'){
      if(!url.searchParams.has('companyId'))return json({companies});
      const model=overviewModel(mismatchOverview?companies[1].id:companyId);
      if(delayOverview&&companyId===companies[0].id){delayOverview=false;await new Promise(r=>releaseOverview=r);}
      return json(url.searchParams.get('view')==='sections'?{model,savedReport:{capturedAt:when,builtAt:when}}:{report:{company:{id:companyId}},model});
    }
    if(p==='customer-saved-sources'){
      if(url.searchParams.get('setup')==='1')return json({companies});
      const source=url.searchParams.get('source');
      if(!source)return sourceState==='blocked' && companyId===companies[1].id
        ?json({companyId,sources:[],blocked:[{source:'crowdstrike',reason:'The saved CrowdStrike import still needs vendor-tenant provenance before registry routing can use it.'}]})
        :json({companyId,sources:[companyId===companies[0].id?'defender':'crowdstrike']});
      const result=savedResult(companyId,source,Number(url.searchParams.get('offset')||0));
      if(delaySource && companyId===companies[0].id){delaySource=false;await new Promise(r=>releaseSource=r);}
      return failSource?json({error:'Fixture saved read failed'},400):json(result);
    }
    if(p==='customer-tiles')return json({canManage:true,storageReady:true,connected:true,crowdstrike:{connected:true},availableSources:{elastic:true,crowdstrike:true},queries:['table','bar'].map(display=>({id:display,title:`Fixture ${display}`,companyId,source:'crowdstrike',query:'fixture',display,chart:{category:'cve',value:'devices'},enabled:false,refreshMinutes:1440,refreshedAt:when,attemptedAt:when,error:null,result:{columns:[{name:'cve',type:'keyword'},{name:'devices',type:'long'}],rows:[[cve,2]],truncated:false}}))});
    if(p==='patch-group-tickets')return json({requests:[summary(companyId)],more:false,total:1});
    if(p==='risk/summary')return json({totalOpenRisk:1,criticalRiskCount:0,swath1Open:0,swath2Open:1,kevOpen:1,internetFacingCriticalRisk:0,verifiedRemediations:0,awaitingVerification:0});
    if(p==='risk/top')return json({rows:[{id:'risk-1',cve,companyId,hostname:'fixture-host',severity:'High',riskScore:720,effectiveSwath:2,calculatedSwath:2,reasons:[],cisaKev:true,epssProbability:0.9,verificationStatus:'detected',lastSeen:when}],total:1});
    if(p==='customer-threat-intelligence')return failIntel?json({error:'Fixture refresh unavailable'},503):json({companyId,available:true,total:1,rows:[{cve,cisa_kev:true,epss_probability:0.9,active_exploitation:true,active_exploitation_source:'MISP',active_exploitation_detail:'Synthetic retained signal',updated_at:when}]});
    if(p==='customer-cve-comparison'){
      assert.equal(req.method(),'GET');
      const result={...detail(companyId),projectionId:published.detailProjection,scope:'published-defender-cohort',enrichmentState:comparisonState==='no-enrichment'?'unavailable':'available',
        enrichment:comparisonState==='no-enrichment'?null:{cvss_score:9.8,epss_probability:0.8,cisa_kev:true,active_exploitation:true,active_exploitation_source:'MISP',active_exploitation_detail:'Saved comparison signal',updated_at:when},
        tickets:[{id:'comparison-reference',ticket_id:444,ticket_url:'https://tickets.invalid/444',state:'created',review_state:'approved',closed:false}],moreTickets:false};
      if(delayComparison){delayComparison=false;await new Promise(resolve=>releaseComparison=resolve);}
      if(companyId===companies[1].id)return json({error:'No verified Defender comparison is configured for this customer.'},409);
      if(comparisonState==='not-ready')return json({error:'Verified version-2 customer projection required'},409);
      return json(result);
    }
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
  await page.getByRole('link',{name:'Open full report',exact:true}).waitFor();
  assert.equal(await page.getByRole('link',{name:'Open full report',exact:true}).getAttribute('href'),`/report/${companies[0].id}`);
  assert.ok(calls.filter(c=>c.path==='reporting'&&c.companyId).every(c=>c.view==='sections'));
  assert.equal(await page.getByLabel('Customer',{exact:true}).count(),1);
  await page.getByText(/Saved platform report as of/).waitFor();
  pass('Overview loads the sections-only contract with one selector and preserves the full-report link');
  await page.getByRole('region',{name:'Highest risk vulnerability findings',exact:true}).getByRole('button',{name:`View ${cve} details`,exact:true}).click();
  await page.getByRole('dialog',{name:cve,exact:true}).getByText(`${companies[0].id}-device`,{exact:true}).waitFor();
  await page.keyboard.press('Escape');
  pass('CVE links in the Overview sections retain the shared patch-request panel');
  const tile=page.getByRole('region',{name:'Fixture table',exact:true});
  await tile.getByRole('button',{name:'Edit',exact:true}).click();
  await page.getByRole('button',{name:'Preview (optional)',exact:true}).click();
  await page.getByRole('button',{name:'Preview (optional)',exact:true}).waitFor();
  await page.getByText('Preview',{exact:true}).waitFor();
  assert.equal(calls.filter(c=>c.path==='preview').length,1);
  assert.equal(calls.filter(c=>c.path===`jobs/${id}`).length,1);
  assert.equal(calls.find(c=>c.path==='preview').body.companyId,companies[0].id);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  pass('optional preview carries the existing selected customer to the queued query without another selector');
  const opener=tile.getByRole('button',{name:`View ${cve} details`});await opener.click();
  const panel=page.getByRole('dialog',{name:cve,exact:true});await panel.getByText(`${companies[0].id}-device`,{exact:true}).waitFor();
  assert.equal(await panel.getByRole('button',{name:'Compare database read',exact:true}).count(),shadowReads?1:0);
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
  await page.keyboard.press('Escape');await page.getByLabel('Customer',{exact:true}).selectOption(companies[1].id);
  await page.getByRole('button',{name:`View ${cve} details`}).first().click();await panel.getByText(`${companies[1].id}-device`,{exact:true}).waitFor();
  releaseDetail();await delay(150);assert.doesNotMatch(await panel.innerText(),/CO-TEST-A-device/);
  await page.setViewportSize({width:390,height:844});const box=await panel.boundingBox();assert.ok(box.width<=390 && box.x>=0);
  await page.keyboard.press('Tab');assert.equal(await panel.evaluate(e=>e.contains(document.activeElement)),true);
  await page.screenshot({path:join(artifacts,'shared-cve-mobile-fixture.png')});
  pass('late previous-customer response is ignored; mobile panel fits and keeps keyboard focus');
  if(savedReads){
    await page.keyboard.press('Escape');await page.setViewportSize({width:1440,height:1000});
    await page.goto(base+`/remediation?companyId=${companies[0].id}&view=prioritize`);
    const saved=page.getByRole('region',{name:'Microsoft Defender saved results'});
    await saved.getByRole('button',{name:cve,exact:true}).waitFor();
    assert.equal(await page.getByLabel('Customer',{exact:true}).count(),1);
    await saved.getByRole('button',{name:cve,exact:true}).click();
    await panel.getByRole('button',{name:'Prepare patch request',exact:true}).waitFor();
    await page.keyboard.press('Escape');
    await saved.getByRole('button',{name:'Next CVEs'}).click();await saved.getByRole('button',{name:'CVE-2026-9999',exact:true}).waitFor();
    assert.equal(await saved.getByRole('button',{name:'Next CVEs'}).isDisabled(),true);
    await saved.getByRole('button',{name:'Previous CVEs'}).click();await saved.getByRole('button',{name:cve,exact:true}).waitFor();
    pass('saved CVE pagination and shared patch panel work with one customer selector');
    sourceState='stale';await saved.getByRole('button',{name:'Refresh saved results'}).click();
    await saved.getByText('These results are older than 36 hours.',{exact:true}).waitFor();
    await saved.getByText('A newer import is waiting for its summary.',{exact:false}).waitFor();
    await saved.getByText('The latest import failed.',{exact:false}).waitFor();
    failSource=true;await saved.getByRole('button',{name:'Refresh saved results'}).click();
    await saved.getByRole('alert').filter({hasText:'Previously loaded results'}).waitFor();
    assert.equal(await saved.getByRole('button',{name:cve,exact:true}).count(),1);failSource=false;
    pass('stale, pending summary, changed connection and failed refresh retain honest completed results');
    delaySource=true;sourceState='available';await saved.getByRole('button',{name:'Refresh saved results'}).click();
    for(let i=0;i<100&&!releaseSource;i++)await delay(20);assert.ok(releaseSource);
    sourceState='pending';await page.getByLabel('Customer',{exact:true}).selectOption(companies[1].id);
    const falcon=page.getByRole('region',{name:'CrowdStrike Spotlight saved results'});
    await falcon.getByText('The import is complete.',{exact:false}).waitFor();releaseSource();await delay(100);
    assert.equal(await saved.count(),0);assert.equal(await falcon.locator('dd').count(),0);
    assert.equal(await falcon.getByRole('button',{name:cve,exact:true}).count(),0);
    pass('pending data is not displayed as zero and late previous-customer results cannot reappear');
    sourceState='available';await falcon.getByRole('button',{name:'Refresh saved results'}).click();await falcon.getByRole('button',{name:cve,exact:true}).waitFor();
    await page.setViewportSize({width:390,height:844});const box=await falcon.boundingBox();assert.ok(box.width<=390&&box.x>=0);
    await page.screenshot({path:join(artifacts,'saved-source-mobile.png'),fullPage:true});
    await page.setViewportSize({width:1440,height:1000});await page.screenshot({path:join(artifacts,'saved-source-desktop.png'),fullPage:true});
    pass('saved result cards fit mobile and CVE rows scroll inside the panel');
    sourceState='blocked';await page.goto(base+`/remediation?companyId=${companies[1].id}&view=prioritize`);
    const savedRegion=page.getByRole('region',{name:'Saved source preview',exact:true});
    await savedRegion.getByText('vendor-tenant provenance',{exact:false}).waitFor();
    assert.equal(await falcon.count(),0);assert.equal(await savedRegion.locator('dd').count(),0);
    await page.getByLabel('Customer',{exact:true}).selectOption(companies[0].id);
    await saved.getByRole('button',{name:cve,exact:true}).waitFor();
    assert.equal(await savedRegion.getByText('vendor-tenant provenance',{exact:false}).count(),0);
    pass('blocked registry selection explains missing source without zero counts or another customer message');
  }
  if(shadowReads){
    await page.setViewportSize({width:1440,height:1000});
    await page.goto(base+`/remediation?companyId=${companies[0].id}&view=overview`);
    const open=async()=>{await page.getByRole('region',{name:'Fixture table',exact:true}).getByRole('button',{name:`View ${cve} details`,exact:true}).click();await panel.getByRole('button',{name:'Prepare patch request',exact:true}).waitFor();};
    await open();const writes=calls.filter(call=>call.method==='POST').length;
    await panel.getByRole('button',{name:'Compare database read',exact:true}).click();
    await panel.getByRole('link',{name:'Ticket #444',exact:true}).waitFor();
    assert.match(await panel.getByRole('note').innerText(),/Defender findings only/);
    assert.match(await panel.innerText(),/MISP.*Saved comparison signal/);
    assert.equal(await panel.getByRole('button',{name:/Prepare patch request|Download host CSV|Create ticket/}).count(),0);
    pass('comparison shows scoped evidence, threat enrichment and saved ticket links without write controls');
    comparisonState='no-enrichment';await panel.getByRole('button',{name:'Return to current data'}).click();
    await panel.getByRole('button',{name:'Compare database read'}).click();
    await panel.getByText('Threat enrichment storage is unavailable.',{exact:true}).waitFor();
    comparisonState='not-ready';await panel.getByRole('button',{name:'Return to current data'}).click();
    await panel.getByRole('button',{name:'Compare database read'}).click();
    await panel.getByRole('alert').filter({hasText:'Verified version-2'}).waitFor();assert.equal(await panel.getByRole('table').count(),0);
    pass('missing enrichment and unready projection are distinct; comparison failures do not display old evidence');
    comparisonState='available';await panel.getByRole('button',{name:'Return to current data'}).click();
    await panel.getByRole('button',{name:'Prepare patch request',exact:true}).waitFor();
    delayComparison=true;await panel.getByRole('button',{name:'Compare database read'}).click();
    for(let i=0;i<100&&!releaseComparison;i++)await delay(20);assert.ok(releaseComparison);
    await panel.getByRole('button',{name:'Return to current data'}).click();releaseComparison();releaseComparison=null;
    await panel.getByRole('button',{name:'Prepare patch request',exact:true}).waitFor();await delay(100);
    assert.equal(await panel.getByRole('link',{name:'Ticket #444'}).count(),0);
    pass('late comparison responses cannot replace the current-data view');
    delayComparison=true;await panel.getByRole('button',{name:'Compare database read'}).click();
    for(let i=0;i<100&&!releaseComparison;i++)await delay(20);assert.ok(releaseComparison);
    await panel.getByRole('button',{name:'Close',exact:true}).click();await page.getByLabel('Customer',{exact:true}).selectOption(companies[1].id);
    releaseComparison();releaseComparison=null;await open();await panel.getByRole('button',{name:'Compare database read'}).click();
    await panel.getByRole('alert').filter({hasText:'No verified Defender comparison'}).waitFor();
    assert.equal(await panel.getByRole('link',{name:'Ticket #444'}).count(),0);
    assert.equal(calls.filter(call=>call.method==='POST').length,writes);
    await page.screenshot({path:join(artifacts,'shadow-cve-unsupported.png'),fullPage:true});
    await panel.getByRole('button',{name:'Close',exact:true}).click();await page.getByLabel('Customer',{exact:true}).selectOption(companies[0].id);await open();
    await panel.getByRole('button',{name:'Compare database read'}).click();await panel.getByRole('link',{name:'Ticket #444'}).waitFor();
    await page.setViewportSize({width:390,height:844});const box=await panel.boundingBox();assert.ok(box.width<=390&&box.x>=0);
    await page.screenshot({path:join(artifacts,'shadow-cve-mobile.png'),fullPage:true});
    pass('customer switching rejects previous results, unsupported customers stay explicit, and comparison fits mobile');
    await panel.getByRole('button',{name:'Close',exact:true}).click();
    await published.run({page,panel,base,pass,artifacts});
  }
  if(!shadowReads){assert.equal(await page.getByRole('button',{name:'Compare published data',exact:true}).count(),0);assert.equal(published.requests.length,0);pass('disabled comparison adds no button or page requests');}
  await page.goto(base+`/remediation?companyId=${companies[0].id}&view=overview`);
  await page.getByRole('link',{name:'Open full report',exact:true}).waitFor();
  mismatchOverview=true;await page.getByRole('button',{name:'Refresh report',exact:true}).click();
  await page.getByRole('alert').filter({hasText:'report returned a different customer'}).waitFor();
  assert.equal(await page.getByRole('link',{name:'Open full report',exact:true}).count(),0);
  assert.equal(await page.getByText(`${companies[1].id}-overview-device`,{exact:true}).count(),0);
  mismatchOverview=false;delayOverview=true;await page.getByRole('button',{name:'Refresh report',exact:true}).click();
  for(let i=0;i<100&&!releaseOverview;i++)await delay(20);assert.ok(releaseOverview);
  await page.getByLabel('Customer',{exact:true}).selectOption(companies[1].id);
  await page.getByText(`${companies[1].id}-overview-device`,{exact:true}).waitFor();releaseOverview();await delay(150);
  assert.equal(await page.getByText(`${companies[0].id}-overview-device`,{exact:true}).count(),0);
  await page.screenshot({path:join(artifacts,'overview-sections-mobile.png'),fullPage:true});
  pass('mismatched and late Overview responses cannot show another customer report');
  await page.goto(base+`/reporting?companyId=${companies[0].id}`);
  await page.getByRole('link',{name:'Open full report',exact:true}).waitFor();
  assert.ok(calls.some(c=>c.path==='reporting'&&c.companyId===companies[0].id&&c.view===null));
  pass('original reporting keeps its full response route and report sections');
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
