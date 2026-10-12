import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
export async function verifyPlatformHttp({request,cookie,deniedCookie,shadow,role,options,database,publish,projection,fixtures}){
  const base='/api/elastic-dashboard/customer-platform-comparison?companyId=CO-A';
  assert.equal((await request(base)).status,401);assert.equal((await request(base,deniedCookie)).status,401);
  assert.equal((await request(base,cookie,'POST')).status,405);
  for(const [query,status] of [
    ['companyId=CO-UNKNOWN',409],['companyId=CO-DEMO',404],['companyId=CO-A&limit=101',400],
    ['companyId=CO-A&limit=1e2',400],['companyId=CO-A&view=cves&status=all',400],
    ['companyId=CO-A&projectionId='+projection,400],['companyId=CO-A&view=cves&view=findings',400],
    ['companyId=CO-A&cursor=broken',400],
  ])assert.equal((await request('/api/elastic-dashboard/customer-platform-comparison?'+query,cookie)).status,status);
  const missing=await request(base.replace('CO-A','CO-B'),cookie);assert.equal(missing.status,200);assert.equal(missing.value.state,'unpublished');
  assert.equal(missing.value.summary,undefined);assert.equal(missing.value.page,undefined);
  const summary=await request(base,cookie);assert.equal(summary.status,200);assert.match(summary.headers.get('cache-control'),/private.*no-store/);
  assert.equal(summary.value.summary.records,3);assert.equal(summary.value.summary.openEndpoint,2);assert.equal(summary.value.page,null);
  const ids=[];let cursor=null;
  do{
    const page=await request(base+'&view=findings&status=all&limit=1'+(cursor?'&cursor='+cursor:''),cookie);
    assert.equal(page.status,200);assert.equal(page.value.page.rows.length,1);assert.equal(page.value.page.total,3);
    assert.ok(!JSON.stringify(page.value).match(/PRIVATE_SOURCE_EXTENSION|NEVER_EXPOSE_PACKET|sourceDetail|preparation|excluded/));
    ids.push(page.value.page.rows[0].id);cursor=page.value.page.nextCursor;
  }while(cursor);
  assert.deepEqual(ids,['F-0','F-1','F-2']);
  const resolved=await request(base+'&view=findings&status=Resolved',cookie);assert.equal(resolved.value.page.total,1);assert.equal(resolved.value.page.rows[0].id,'F-2');
  const group=await request(base+'&view=cves',cookie);assert.equal(group.value.page.total,1);assert.equal(group.value.page.rows[0].findings,2);assert.equal(group.value.page.rows[0].affectedDevices,2);
  let revision=summary.value.publication.revision;
  await publish(fixtures.list,revision++);
  const list=await request(base+'&view=findings&limit=100',cookie);assert.equal(list.status,200);
  assert.equal(list.value.page.rows.length,100);assert.equal(list.value.page.total,105);
  const oldCursor=list.value.page.nextCursor;assert.ok(oldCursor);
  const second=await request(base+'&view=findings&limit=100&cursor='+oldCursor,cookie);
  assert.equal(second.value.page.rows.length,5);assert.equal(second.value.page.nextCursor,null);
  assert.deepEqual([...list.value.page.rows,...second.value.page.rows].map(r=>r.id),fixtures.rows.map(r=>r.id));
  const cv1=await request(base+'&view=cves&limit=100',cookie);
  const cv2=await request(base+'&view=cves&limit=100&cursor='+cv1.value.page.nextCursor,cookie);
  const rank={Critical:3,High:2,Low:1};
  assert.deepEqual([...cv1.value.page.rows,...cv2.value.page.rows].map(r=>r.cve),[...fixtures.rows].sort((a,b)=>rank[b.severity]-rank[a.severity]||a.cve.localeCompare(b.cve)).map(r=>r.cve));
  assert.equal(cv2.value.page.nextCursor,null);
  assert.equal((await request(base+'&view=cves&cursor='+oldCursor,cookie)).status,400);
  assert.equal((await request(base.replace('CO-A','CO-B')+'&view=findings&cursor='+oldCursor,cookie)).status,400);

  const blocker=new pg.Client({...options,database});await blocker.connect();let pending;
  try{
    await blocker.query('BEGIN');await blocker.query('LOCK TABLE defender_shadow_priority IN ACCESS EXCLUSIVE MODE');
    const pid=(await blocker.query('SELECT pg_backend_pid() pid')).rows[0].pid;
    pending=request(base+'&view=findings',cookie);
    let blocked=false;
    for(let i=0;i<100;i++){
      blocked=(await shadow.query(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
        AND usename=$1 AND $2=ANY(pg_blocking_pids(pid)) AND query LIKE '%defender_shadow_priority%') blocked`,[role,pid])).rows[0].blocked;
      if(blocked)break;await delay(20);
    }
    assert.ok(blocked,'Published page must pause after selecting its generation');
    await publish(fixtures.empty,revision++);
  }finally{await blocker.query('ROLLBACK');await blocker.end();}
  const retained=await pending;assert.equal(retained.status,200);assert.equal(retained.value.page.total,105);
  assert.equal(retained.value.projectionId,fixtures.list);assert.equal(retained.value.publication.revision,revision-1);
  const stale=await request(base+'&view=findings&cursor='+oldCursor,cookie);assert.equal(stale.status,409);assert.match(stale.value.error,/Restart/);
  for(const view of ['summary','findings','cves']){
    const empty=await request(base+'&view='+view,cookie);assert.equal(empty.status,200);assert.equal(empty.value.state,'available');
    assert.equal(empty.value.summary.records,0);if(view!=='summary'){assert.equal(empty.value.page.total,0);assert.deepEqual(empty.value.page.rows,[]);}
  }
  await publish(fixtures.oversized,revision++);
  const tooLarge=await request(base+'&view=findings',cookie);assert.equal(tooLarge.status,413);assert.ok(JSON.stringify(tooLarge.value).length<512);
  assert.equal((await request(base,cookie)).value.summary.records,1);
  await publish(projection,revision++);
  assert.equal((await request(base,cookie)).value.summary.records,3);
  return {checks:5,maxReturnedRows:100,findingsTraversed:105,cvesTraversed:105,publicationRevision:revision};
}
