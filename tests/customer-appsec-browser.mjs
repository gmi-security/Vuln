// Real local production UI; every customer/source API uses synthetic fixtures.
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
for (const file of ['.env', '.env.local', '.env.production', '.env.production.local']) assert.equal(existsSync(file), false, 'Use an unconfigured checkout');
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');
const reserve = createServer().listen(0, '127.0.0.1'); await once(reserve, 'listening');
const port = reserve.address().port; await new Promise(r => reserve.close(r));
const base = `http://127.0.0.1:${port}`, secret = randomBytes(32).toString('hex');
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(PATH|PATHEXT|SYSTEMROOT|WINDIR|TEMP|TMP|COMSPEC|USERPROFILE|APPDATA|LOCALAPPDATA)$/i.test(key)));
Object.assign(env, { NODE_ENV: 'production', NEXTAUTH_URL: base, NEXTAUTH_SECRET: secret, VULN_DISABLE_SCHEDULER: 'true', ELASTIC_VULN_ENABLED: 'true', VULN_REMEDIATION_UI: 'true', VULN_REVIEWED_APPSEC_PROVIDERS: 'appsec' });
const server = spawn(process.execPath, ['node_modules/next/dist/bin/next', 'start', '-H', '127.0.0.1', '-p', String(port)], { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
let output = ''; server.stdout.on('data', d => output += d); server.stderr.on('data', d => output += d);
let browser, page, checks = 0; const pass = message => { checks++; console.log('PASS ' + message); };
const artifacts = await mkdtemp(join(tmpdir(), 'vuln2-appsec-browser-'));
const companies=[{id:'CO-A',name:'Fixture Alpha'},{id:'CO-B',name:'Fixture Beta'},{id:'CO-EMPTY',name:'No AppSec approval'}];
const calls=[],errors=[],unexpected=[];let fail=false,mismatch=false,reviewed=true,pending=false,release;
function summary(id){const repo=id==='CO-B'?'Fixture/Beta':'Fixture/Alpha';return {repositories:1,totalRepositories:2,coveragePct:50,findings:7,vulnerabilities:6,misconfigurations:1,licenses:0,gateFailures:1,critical:2,high:3,newCritical:1,newHigh:1,secrets:0,resolved:4,
 rows:[{repository:repo,lastScan:'2026-10-10T12:00:00Z',findings:7,vulnerabilities:6,misconfigurations:1,licenses:0,critical:2,high:3,medium:2,low:0,secrets:0,newFindings:2,newCritical:1,newHigh:1,resolved:4,gate:'fail'}]};}
try {
 let ready=false;for(let i=0;i<100;i++){try{if((await fetch(base+'/login')).ok){ready=true;break;}}catch{}await delay(100);}assert.ok(ready,output);
 for(const path of ['/api/appsec?setup=1','/api/appsec?companyId=CO-A','/api/appsec/repositories/Fixture%2FAlpha?companyId=CO-A'])
  assert.equal((await fetch(base+path,{redirect:'manual'})).status,401);
 pass('real proxy requires authentication for setup, summary and repository APIs');
 browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHANNEL?{channel:process.env.PLAYWRIGHT_CHANNEL}:{})});
 const context=await browser.newContext({viewport:{width:1440,height:1050}});
 const token=await encode({secret,token:{name:'Fixture member',orgMember:true,orgRole:'MEMBER'},maxAge:300});
 await context.addCookies([{name:'next-auth.session-token',value:token,url:base}]);
 page=await context.newPage();page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());if(url.origin!==base)return route.abort();
  if(!url.pathname.startsWith('/api/'))return route.continue();
  const id=url.searchParams.get('companyId');calls.push({path:url.pathname,company:id,method:request.method()});
  const json=(body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)}).catch(()=>{});
  if(url.pathname==='/api/auth/session')return json({user:{name:'Fixture member'},expires:'2099-01-01T00:00:00Z'});
  if(url.pathname==='/api/connectors')return json({connectors:[]});
  if(url.pathname==='/api/connectors/sync-all')return json({status:null});
  if(url.pathname==='/api/elastic-vulnerabilities/status')return json({enabled:true,remediationEnabled:true});
  if(url.pathname==='/api/appsec'){
   if(url.searchParams.get('setup')==='1')return json({reviewed,companies:reviewed?companies:[]});
   if(pending&&id==='CO-A'){pending=false;await new Promise(r=>release=r);}
   if(fail||id==='CO-EMPTY')return json({companyId:id,configured:true,error:'AppSec repository approval is unavailable.',summary:null,trend:null},409);
   return json({companyId:mismatch?'OTHER':id,configured:true,summary:summary(id),trend:[],trendError:id==='CO-B'?'AppSec trend is unavailable. Summary results are still shown.':null});
  }
  if(url.pathname.startsWith('/api/appsec/repositories/')){
   if(id!=='CO-A'||decodeURIComponent(url.pathname.split('/').at(-1))!=='Fixture/Alpha'){unexpected.push('Repository scope '+url.pathname);return json({error:'Fixture scope mismatch'},409);}
   return json({companyId:id,configured:true,detail:{repository:'Fixture/Alpha',scans:[{scanId:'scan-fixture',completedAt:'2026-10-10T12:00:00Z',status:'completed',findings:250,critical:2,high:3,newCritical:1,newHigh:1,resolved:4,gate:'fail'}],
     findings:[{fingerprint:'fp',id:'fixture',severity:'High',kind:'vulnerability',vulnerabilityId:'CVE-2026-1234',title:'Update fixture package',package:'fixture-pkg',target:null,status:'open',observedAt:'2026-10-10T12:00:00Z'}],findingsError:null,findingsTruncated:true}});
  }
  unexpected.push(url.pathname);return json({error:'Unexpected fixture request'},500);
 });
 await page.goto(base+'/appsec');const select=()=>page.getByLabel('Customer',{exact:true});await select().waitFor();
 assert.equal(await select().count(),1);assert.equal(calls.filter(c=>c.path==='/api/appsec'&&c.company).length,0);
 await page.getByText('Choose a customer to view its approved AppSec repositories.',{exact:true}).waitFor();
 await select().selectOption('CO-A');await page.getByRole('link',{name:/Fixture\/Alpha/}).waitFor();
 await page.waitForURL(/companyId=CO-A/);assert.equal(await page.getByRole('link',{name:/Fixture\/Beta/}).count(),0);
 await page.getByText(/Coverage uses the approved repository list/).waitFor();
 await page.waitForFunction(()=>[...document.querySelectorAll('span')].find(s=>s.textContent==='Coverage %')?.previousElementSibling?.textContent==='50');
 await page.screenshot({path:join(artifacts,'appsec-customer-desktop.png'),fullPage:true});
 pass('one customer selector gates reads and summary coverage reflects the approved repository list');
 await page.getByRole('link',{name:/Fixture\/Alpha/}).click();await page.getByRole('heading',{name:'Fixture/Alpha',exact:true}).waitFor();
 await page.getByText('Update fixture package',{exact:true}).waitFor();await page.getByText('Showing the first 100 findings.',{exact:false}).waitFor();
 await page.waitForURL(/companyId=CO-A/);assert.match(await page.getByRole('link',{name:'All repositories',exact:true}).getAttribute('href'),/companyId=CO-A/);
 await page.getByRole('link',{name:'All repositories',exact:true}).click();await select().waitFor();assert.equal(await select().inputValue(),'CO-A');
 pass('repository drilldown and return retain the customer and visibly label capped findings');
 await select().selectOption('CO-B');await page.getByRole('link',{name:/Fixture\/Beta/}).waitFor();
 await page.getByText('AppSec trend is unavailable. Summary results are still shown.',{exact:true}).waitFor();
 assert.equal(await page.getByRole('link',{name:/Fixture\/Alpha/}).count(),0);
 pending=true;await select().selectOption('CO-A');await page.waitForFunction(()=>document.querySelector('select')?.value==='CO-A');
 for(let i=0;i<100&&!release;i++)await delay(20);assert.ok(release);
 await select().selectOption('CO-B');await page.getByRole('link',{name:/Fixture\/Beta/}).waitFor();release();await delay(150);
 assert.equal(await page.getByRole('link',{name:/Fixture\/Alpha/}).count(),0);
 pass('customer switches clear prior results and discard a delayed response for the previous customer');
 fail=true;await page.getByRole('button',{name:'Refresh',exact:true}).click();await page.getByText('AppSec repository approval is unavailable.',{exact:true}).waitFor();
 assert.equal(await page.getByRole('link',{name:/Fixture\/Beta/}).count(),0);
 fail=false;mismatch=true;await page.getByRole('button',{name:'Refresh',exact:true}).click();await page.getByText('Failed to reach the API.',{exact:true}).waitFor();
 assert.equal(await page.getByRole('link',{name:/Fixture\/Alpha|Fixture\/Beta/}).count(),0);
 mismatch=false;await select().selectOption('CO-EMPTY');await page.getByText('AppSec repository approval is unavailable.',{exact:true}).waitFor();
 pass('revocation, response scope mismatch and unapproved customers expose no old or organization results');
 await select().selectOption('CO-A');await page.getByRole('link',{name:/Fixture\/Alpha/}).waitFor();await page.setViewportSize({width:390,height:844});
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
 await page.waitForFunction(()=>[...document.querySelectorAll('span')].find(s=>s.textContent==='Coverage %')?.previousElementSibling?.textContent==='50');
 await page.screenshot({path:join(artifacts,'appsec-customer-mobile.png'),fullPage:true});
 pass('customer summary fits mobile width while repository rows scroll horizontally');
 reviewed=false;await page.goto(base+'/appsec');await page.getByRole('link',{name:/Fixture\/Alpha/}).waitFor();assert.equal(await select().count(),0);
 assert.ok(calls.some(c=>c.path==='/api/appsec'&&c.company===null));
 assert.ok(calls.every(c=>c.method==='GET'));assert.deepEqual(unexpected,[]);assert.deepEqual(errors,[]);
 pass('legacy organization view remains available with routing off; no mutation API is invoked');
 await writeFile(join(artifacts,'result.json'),JSON.stringify({checks,calls,errors,unexpected},null,2));console.log(JSON.stringify({passed:checks,artifacts}));
} catch(error){await page?.screenshot({path:join(artifacts,'failure.png'),fullPage:true}).catch(()=>{});console.error(JSON.stringify({artifacts,url:page?.url(),errors,unexpected,body:(await page?.locator('body').innerText().catch(()=>''))?.slice(0,1500)}));throw error;
}finally{release?.();await browser?.close();server.kill();await once(server,'exit').catch(()=>{});}
