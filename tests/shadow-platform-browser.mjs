// Synthetic responses for the real built Remediation UI. No database or vendors.
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {join} from 'node:path';

export function publishedComparisonFixture({companies,cve,when,id,calls}){
  let state='available',hold=false,release;
  const requests=[];
  const fixture={requests,detailProjection:id,async handle({req,url,json}){
    assert.equal(req.method(),'GET');const companyId=url.searchParams.get('companyId'),view=url.searchParams.get('view'),cursor=url.searchParams.get('cursor');
    requests.push(Object.fromEntries(url.searchParams));assert.equal(url.searchParams.get('limit'),'50');
    const current=state;
    const value={state:current==='unpublished'?'unpublished':'available',scope:'published-defender-cohort',companyId,projectionId:id,
      publication:{revision:1,publishedAt:when},summary:{openRemediation:51,uniqueOpenCves:51,affectedDeviceIds:2},
      page:{total:51,nextCursor:cursor?null:'fixture-next',rows:[view==='findings'?{id:cursor?'second':'first',cve:cursor?'CVE-2026-9999':cve,asset:`${companyId}-published`,severity:'High',realRisk:72,cvss:8.1,status:'Open'}:{cve:cursor?'CVE-2026-9999':cve,severity:'High',affectedDevices:2,findings:2,realRisk:72,cvss:8.1}]}};
    if(current==='unpublished'){delete value.summary;delete value.page;}
    if(current==='empty'){value.summary={openRemediation:0,uniqueOpenCves:0,affectedDeviceIds:0};value.page={total:0,rows:[],nextCursor:null};}
    if(current==='large')value.page.rows=Array.from({length:50},(_,i)=>({...value.page.rows[0],id:`fixture-${i}`,cve:`CVE-2026-${1000+i}`}));
    if(current==='wrong-customer')value.companyId='CO-WRONG';
    if(hold){hold=false;await new Promise(resolve=>release=resolve);}
    if(current==='changed'&&cursor)return json({error:'Published comparison changed. Restart from the first page.'},409);
    if(current==='failed')return json({error:'Fixture page unavailable'},503);
    return json(value);
  },async run({page,panel,base,pass,artifacts}){
    await page.setViewportSize({width:1440,height:1000});
    await page.goto(base+`/remediation?companyId=${companies[0].id}&view=overview`);
    const writes=calls.filter(c=>c.method==='POST').length;
    const open=page.getByRole('button',{name:'Compare published data',exact:true});
    await open.waitFor();assert.equal(requests.length,0);
    assert.equal(await page.getByLabel('Customer',{exact:true}).count(),1);
    await open.click();const region=page.getByRole('region',{name:'Published data comparison',exact:true});
    const rows=region.getByRole('region',{name:'Comparison rows',exact:true});
    await rows.getByRole('button',{name:cve,exact:true}).waitFor();
    await region.getByRole('button',{name:'Next page',exact:true}).click();await rows.getByRole('button',{name:'CVE-2026-9999',exact:true}).waitFor();
    assert.equal(requests.at(-1).cursor,'fixture-next');
    await region.getByRole('button',{name:'Previous page',exact:true}).click();await rows.getByRole('button',{name:cve,exact:true}).waitFor();assert.equal(requests.at(-1).cursor,undefined);
    await region.getByRole('button',{name:'Next page',exact:true}).click();await rows.getByRole('button',{name:'CVE-2026-9999',exact:true}).waitFor();
    await region.getByLabel('Workflow').selectOption('Resolved');await rows.getByRole('button',{name:cve,exact:true}).waitFor();assert.equal(requests.at(-1).status,'Resolved');assert.equal(requests.at(-1).cursor,undefined);
    await region.getByRole('button',{name:'CVEs',exact:true}).click();await rows.getByRole('columnheader',{name:'Affected devices',exact:true}).waitFor();assert.equal(requests.at(-1).status,'open');
    pass('published comparison is opt-in, reuses customer selector and resets bounded pages on view and workflow changes');
    state='changed';await region.getByRole('button',{name:'Next page',exact:true}).click();await region.getByRole('alert').waitFor();assert.equal(await rows.count(),0);
    await region.getByRole('button',{name:'Restart from first page',exact:true}).click();await rows.getByRole('button',{name:cve,exact:true}).waitFor();assert.equal(requests.at(-1).cursor,undefined);
    state='unpublished';await region.getByRole('button',{name:'Refresh comparison',exact:true}).click();await region.getByText(/No verified publication/).waitFor();assert.equal(await region.getByRole('definition').count(),0);
    state='empty';await region.getByRole('button',{name:'Refresh comparison',exact:true}).click();await region.getByText(/No records match/).waitFor();assert.deepEqual(await region.getByRole('definition').allTextContents(),['0','0','0']);
    state='failed';await region.getByRole('button',{name:'Refresh comparison',exact:true}).click();await region.getByRole('alert').filter({hasText:'Fixture page unavailable'}).waitFor();assert.equal(await rows.count(),0);
    state='wrong-customer';await region.getByRole('button',{name:'Retry comparison',exact:true}).click();await region.getByRole('alert').filter({hasText:'did not match'}).waitFor();
    state='available';await region.getByRole('button',{name:'Retry comparison',exact:true}).click();await rows.getByRole('button',{name:cve,exact:true}).waitFor();
    pass('changed publication requires first-page restart; missing, empty, failed and mismatched responses stay distinct');
    const normalReads=calls.filter(c=>c.path==='customer-cve').length;
    await rows.getByRole('button',{name:cve,exact:true}).click();await panel.getByRole('link',{name:'Ticket #444'}).waitFor();
    assert.equal(await panel.getByRole('button',{name:/Prepare patch|Download host|Create ticket|Return to current/}).count(),0);
    assert.equal(calls.filter(c=>c.path==='customer-cve').length,normalReads);
    await page.keyboard.press('Escape');assert.equal(await rows.getByRole('button',{name:cve,exact:true}).evaluate(e=>e===document.activeElement),true);
    fixture.detailProjection='00000000-0000-4000-8000-000000000002';
    await rows.getByRole('button',{name:cve,exact:true}).click();await panel.getByRole('alert').filter({hasText:'Publication changed'}).waitFor();assert.equal(await panel.getByRole('table').count(),0);
    await page.keyboard.press('Escape');fixture.detailProjection=id;
    pass('listed CVEs open only the read-only shared panel and reject detail from a different publication');
    const pending=async()=>{for(let i=0;i<100&&!release;i++)await delay(20);assert.ok(release);};
    hold=true;await region.getByRole('button',{name:'Refresh comparison',exact:true}).click();await pending();
    await region.getByRole('button',{name:'Findings',exact:true}).click();await rows.getByRole('columnheader',{name:'Asset',exact:true}).waitFor();release();release=null;await delay(100);assert.equal(await rows.getByRole('columnheader',{name:'Affected devices',exact:true}).count(),0);
    hold=true;await region.getByRole('button',{name:'Next page',exact:true}).click();await pending();
    await page.getByLabel('Customer',{exact:true}).selectOption(companies[1].id);await open.waitFor();release();release=null;await delay(100);assert.equal(await region.count(),0);
    await open.click();await rows.getByText(`${companies[1].id}-published`,{exact:true}).waitFor();assert.equal(await rows.getByText(`${companies[0].id}-published`,{exact:true}).count(),0);assert.equal(requests.at(-1).cursor,undefined);
    hold=true;await region.getByRole('button',{name:'Refresh comparison',exact:true}).click();await pending();
    await page.getByRole('button',{name:'Close published comparison',exact:true}).click();release();release=null;await delay(100);assert.equal(await region.count(),0);
    await open.click();await rows.getByRole('table').waitFor();
    pass('late pages cannot replace a changed view, customer or closed comparison');
    state='large';await region.getByRole('button',{name:'Refresh comparison',exact:true}).click();await rows.getByRole('button',{name:'CVE-2026-1049',exact:true}).waitFor();
    await page.setViewportSize({width:390,height:844});
    const box=await region.boundingBox();assert.ok(box.x>=0&&box.x+box.width<=391);
    assert.ok(await rows.evaluate(e=>e.clientHeight<=384&&e.scrollHeight>e.clientHeight&&e.scrollWidth>e.clientWidth));
    await page.screenshot({path:join(artifacts,'published-comparison-mobile.png'),fullPage:true});
    await page.setViewportSize({width:1440,height:1000});await page.screenshot({path:join(artifacts,'published-comparison-desktop.png'),fullPage:true});
    assert.equal(calls.filter(c=>c.method==='POST').length,writes);
    pass('published comparison fits mobile, scrolls inside its table and performs no writes');
  }};
  return fixture;
}
