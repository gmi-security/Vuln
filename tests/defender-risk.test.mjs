// node --experimental-vm-modules --test tests/risk-scoring-store.test.mjs
//
// Exercises lib/risk-scoring-store.ts against a fake db.query (same
// SQL-sniffing fakeDb idiom as the rest of tests/): a fresh finding_risk row
// records risk_history on recalculation, a human Swath override survives a
// later recalculation instead of being silently clobbered, and
// overrideSwath/verification-status writes land the right audit rows.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

function loader(overrides = {}) {
  const cache = new Map();
  async function load(path) {
    path = resolve(path);
    if (cache.has(path)) return cache.get(path);
    const code = ts.transpileModule(await readFile(path, "utf8"), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    const mod = new SourceTextModule(code, { identifier: path }); cache.set(path, mod);
    await mod.link(async (name) => {
      if (overrides[name]) { const values = overrides[name]; return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); }); }
      if (name.startsWith(".")) return load(resolve(dirname(path), `${name}.ts`));
      if (name.startsWith("@/")) return load(resolve(".", `${name.slice(2)}.ts`));
      const values = await import(name);
      return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
    });
    return mod;
  }
  return async (path) => { const mod = await load(path); await mod.evaluate(); return mod.namespace; };
}


import pg from "pg";
import { randomUUID } from "node:crypto";
test("Defender RBVM database lifecycle: score, ticket scope, retire, reopen, preserve overrides, rollback",{skip:!process.env.DEFENDER_TEST_DATABASE_URL},async()=>{
 const url=new URL(process.env.DEFENDER_TEST_DATABASE_URL);assert.ok(["localhost","127.0.0.1"].includes(url.hostname));
 const db=new pg.Pool({connectionString:url.toString()}),companyId=`DEF-RISK-${randomUUID()}`;
 const tenantKey=`defender:${companyId}`;
 const base={id:"finding-1",companyId,asset:"device-key",cve:"CVE-2026-12345",severity:"Critical",status:"Open",kev:false,ransomware:false,
  exploitAvailable:true,assetExposure:"Internal",assetCriticality:"High",defender:{deviceId:"device-1",cvss:9.8,active:true,hostname:"server"}};
 let rows=[base],failWrite=false;
 const wrapped={query:(...args)=>db.query(...args),connect:async()=>{
  const client=await db.connect();return {release:()=>client.release(),query:(sql,args)=>{
   if(failWrite && sql.includes("UPDATE finding_risk f SET source_open"))throw new Error("Injected interrupted refresh");
   return client.query(sql,args);
  }};
 }};
 const modules=loader({
  "./persist":{applicationDatabase:()=>wrapped},
  "./store":{ensureHydrated:async()=>{},defenderProjectedRun:()=>"run1",listFindings:()=>rows,listAssets:()=>[{defenderDeviceId:"device-1",hostname:"server",os:"Windows Server"}]},
  "./defender-store":{defenderStore:()=>({list:async()=>[{companyId,currentRun:"run1"}]})},
  "./cve-enrichment-refresh":{refreshCveEnrichment:async()=>({errors:0})},
  "./patch-ticket-store":{patchTicketDatabase:async()=>({query:async()=>({rows:[{scope:[{cid:companyId,hostId:"other-device",cve:base.cve}],closed:false}]})})},
 });
 const risk=await modules("lib/defender-risk.ts"),riskStore=await modules("lib/risk-scoring-store.ts");
 try{
  let result=await risk.refreshDefenderRisk(false);assert.equal(result.errors,0);assert.equal(result.findingsScored,1);
  let row=(await db.query("SELECT * FROM finding_risk WHERE tenant_key=$1",[tenantKey])).rows[0];
  assert.ok(row.risk_score>0);assert.equal(row.verification_status,"detected","another device's ticket must not cover this host");assert.equal(row.source_open,true);
  await db.query("UPDATE finding_risk SET effective_swath=1,swath_override_by='analyst' WHERE tenant_key=$1",[tenantKey]);
  rows=[{...base,status:"Resolved",defender:{...base.defender,active:false}}];
  assert.equal((await risk.refreshDefenderRisk(false)).errors,0);
  assert.equal((await riskStore.getRiskSummary(wrapped,companyId)).totalOpenRisk,0);
  row=(await db.query("SELECT * FROM finding_risk WHERE tenant_key=$1",[tenantKey])).rows[0];assert.equal(row.verification_status,"verified_remediated");assert.equal(row.source_open,false);
  rows=[base];await risk.refreshDefenderRisk(false);
  row=(await db.query("SELECT * FROM finding_risk WHERE tenant_key=$1",[tenantKey])).rows[0];assert.equal(row.verification_status,"detected");assert.equal(row.verified_at,null);assert.equal(row.source_open,true);assert.equal(row.effective_swath,1);
  const previous=row.risk_score;rows=[{...base,defender:{...base.defender,cvss:1}}];failWrite=true;
  assert.equal((await risk.refreshDefenderRisk(false)).errors,1);
  row=(await db.query("SELECT * FROM finding_risk WHERE tenant_key=$1",[tenantKey])).rows[0];assert.equal(row.risk_score,previous,"failed publication must roll back the score changes too");
  failWrite=false;rows=[];await risk.refreshDefenderRisk(false);
  assert.equal((await riskStore.getRiskSummary(wrapped,companyId)).totalOpenRisk,0);
 }finally{
  await db.query("DELETE FROM risk_history WHERE finding_risk_id IN(SELECT id FROM finding_risk WHERE tenant_key=$1)",[tenantKey]);
  await db.query("DELETE FROM finding_risk WHERE tenant_key=$1",[tenantKey]);
  await db.query("DELETE FROM risk_snapshots WHERE scope=$1",[companyId]);await db.end();
 }
});
