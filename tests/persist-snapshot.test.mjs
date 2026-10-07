// Disposable localhost PostgreSQL only. No application or production credentials.
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import * as crypto from "node:crypto";
import { SourceTextModule, SyntheticModule } from "node:vm";
import ts from "typescript";
import pg from "pg";

const url=process.env.DEFENDER_TEST_DATABASE_URL;
if(url && !["localhost","127.0.0.1","::1"].includes(new URL(url).hostname))throw new Error("Tests require disposable localhost PostgreSQL");
const fixture = (run="run-1",count=5000) => ({
  companies:[["CO-TEST",{id:"CO-TEST",name:"Example Customer"}]],assets:[],scans:[],folders:[],counter:1000,
  findings:Array.from({length:count},(_,i)=>[`DEF-${i}`,{id:`DEF-${i}`,companyId:"CO-TEST",cve:`CVE-2026-${10000+i}`,
    status:"Open",severity:"Critical",remediation:"Install the recommended update",defender:{runId:run,active:true}}]),
  meta:{defenderGenerations:{"CO-TEST":run}},
});
async function harness(t) {
  const schema=`snapshot_${randomUUID().replaceAll("-","")}`,db=new pg.Pool({connectionString:url});
  await db.query(`CREATE SCHEMA ${schema}`);
  const pool=new pg.Pool({connectionString:url,options:`-c search_path=${schema}`});
  t.after(async()=>{await pool.end();await db.query(`DROP SCHEMA ${schema} CASCADE`);await db.end();});
  let upserts=0,fail=false,readHook;
  const wrapper={on(){},end:()=>pool.end(),query:(...args)=>pool.query(...args),connect:async()=>{
    const client=await pool.connect();return {release:error=>client.release(error),query:async(sql,params)=>{
      if(sql.startsWith("INSERT INTO vuln_store")){
        upserts++;if(fail && params[0] === "findings:01")throw new Error("simulated shard write failure");
      }
      const result=await client.query(sql,params);
      if(sql.startsWith("SELECT data FROM vuln_store") && readHook){const fn=readHook;readHook=undefined;await fn();}
      return result;
    }};
  }};
  const code=ts.transpileModule(await readFile("lib/persist.ts","utf8"),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  async function freshModule() {
    const mod=new SourceTextModule(code);
    await mod.link(async name=>{
      const values=name === "pg" ? {Pool:class{constructor(){return wrapper;}}} : crypto;
      return new SyntheticModule(Object.keys(values),function(){for(const key of Object.keys(values))this.setExport(key,values[key]);});
    });
    await mod.evaluate();return mod.namespace;
  }
  // The real Pool is replaced above; this dummy URL only enables persistence.
  const previous=process.env.DATABASE_URL;process.env.DATABASE_URL="postgresql://localhost/test-only";
  t.after(()=>{if(previous === undefined)delete process.env.DATABASE_URL;else process.env.DATABASE_URL=previous;});
  return {pool,freshModule,persist:await freshModule(),writes:()=>upserts,fail:()=>{fail=true;},recover:()=>{fail=false;},hook:fn=>{readHook=fn;}};
}

test("large atomic snapshot round-trips and a restarted process skips unchanged shards",{skip:!url},async t=>{
  const h=await harness(t),data=fixture("run-1",12000);
  let ticks=0,running=true;
  const heartbeat=()=>{if(running){ticks++;setImmediate(heartbeat);}};setImmediate(heartbeat);
  try{await h.persist.saveSnapshot(data);}finally{running=false;}
  assert.ok(ticks>2,"snapshot processing must yield for other requests");
  const reader=await h.freshModule(),loaded=await reader.loadSnapshot();
  assert.equal(loaded.findings.length,12000);assert.equal(loaded.meta.defenderGenerations["CO-TEST"],"run-1");
  const writes=h.writes();await reader.saveSnapshot(loaded);
  assert.equal(h.writes(),writes,"hydration must seed hashes so boot does not rewrite every shard");
  loaded.findings[0][1].status="In Remediation";await reader.saveSnapshot(loaded);
  assert.equal(h.writes()-writes,1,"only the changed finding bucket is written");
});

test("failed publication rolls back all shards and retry saves findings with their generation",{skip:!url},async t=>{
  const h=await harness(t);await h.persist.saveSnapshot(fixture("run-1"));
  h.fail();await assert.rejects(h.persist.saveSnapshot(fixture("run-2")),/simulated shard write failure/);
  const old=await (await h.freshModule()).loadSnapshot();
  assert.equal(old.meta.defenderGenerations["CO-TEST"],"run-1");
  assert.ok(old.findings.every(([,row])=>row.defender.runId === "run-1"));
  h.recover();await h.persist.saveSnapshot(fixture("run-2"));
  const saved=await (await h.freshModule()).loadSnapshot();
  assert.equal(saved.meta.defenderGenerations["CO-TEST"],"run-2");
  assert.ok(saved.findings.every(([,row])=>row.defender.runId === "run-2"));
});

test("hydration cannot mix an old finding shard with a concurrently published generation marker",{skip:!url},async t=>{
  const h=await harness(t);await h.persist.saveSnapshot(fixture("run-1"));
  h.hook(async()=>{const writer=await h.freshModule();await writer.saveSnapshot(fixture("run-2"));});
  const loaded=await (await h.freshModule()).loadSnapshot();
  assert.equal(loaded.meta.defenderGenerations["CO-TEST"],"run-1");
  assert.ok(loaded.findings.every(([,row])=>row.defender.runId === "run-1"));
  const latest=await (await h.freshModule()).loadSnapshot();assert.equal(latest.meta.defenderGenerations["CO-TEST"],"run-2");
});
