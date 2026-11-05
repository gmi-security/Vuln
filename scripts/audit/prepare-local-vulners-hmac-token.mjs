#!/usr/bin/env node
// GMI historical Greenbone recovery comparison, PART 1 (application host).
// READ ONLY. HMACs the company's existing host/CVE pairs so the scanner can
// compare with report-backed historical results without exporting targets.
// The one-time 256-bit key is supplied via GMI_AUDIT_HMAC_HEX in the shell.
// Print only the base64-gzip token to stdout; operational counts go to stderr.
// Do not share or commit the key. No database writes, scanner API, or launching.
import { createHmac, randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const fromRepo=createRequire(resolve(process.cwd(),"package.json"));
const pg=fromRepo("pg");
const {applicationDatabaseSsl}=await import(pathToFileURL(
  resolve(process.cwd(),"lib/db/connection-target.mjs")
).href);
const keyHex=process.env.GMI_AUDIT_HMAC_HEX || "";
if (!/^[0-9a-fA-F]{64}$/.test(keyHex))
  throw Error("GMI_AUDIT_HMAC_HEX must be a private 32-byte random hex value");
const key=Buffer.from(keyHex,"hex");
const hmac=(company,target,cve)=>createHmac("sha256",key).update(
  company+"\0"+target.trim().toLowerCase().replace(/\.$/,"")+"\0"+cve.trim().toUpperCase()
).digest("hex");
const companies=["CO-9150","CO-9153","CO-9156","CO-9159","CO-9162","CO-9165"];
const url=process.env.DATABASE_URL;
if (!url) throw Error("DATABASE_URL missing");
const db=new pg.Client({
  connectionString:url,ssl:applicationDatabaseSsl(url),
  connectionTimeoutMillis:7000,query_timeout:20000
});
try {
  await db.connect();
  await db.query("BEGIN READ ONLY");
  await db.query("SET LOCAL statement_timeout='20s'");
  const {rows:scans}=await db.query(
    "SELECT id,company_id FROM public.app_scans WHERE connector='vulners' AND lower(status)='running' AND company_id=ANY($1::text[]) ORDER BY id",
    [companies]
  );
  if (scans.length!==91 || scans.some(s=>!/^SCAN-\d+$/.test(s.id)))
    throw Error("Local Running inventory changed; re-audit before comparing");
  const {rows:findings}=await db.query(
    "SELECT company_id,asset,cve FROM public.app_findings WHERE connector='vulners' AND company_id=ANY($1::text[])",
    [companies]
  );
  if (findings.length!==82 || findings.some(f=>typeof f.asset!=="string"||
      typeof f.cve!=="string" || !/^CVE-\d{4}-\d{4,}$/i.test(f.cve.trim())))
    throw Error("Local findings inventory changed or includes unsupported CVE");
  const existing=new Set(findings.map(f=>hmac(f.company_id,f.asset,f.cve)));
  if (existing.size!==82) throw Error("Existing findings contain an ambiguous duplicate HMAC identity");
  const payload={
    version:1,
    purpose:"gmi-vulners-historical-host-cve-readonly",
    scanOwners:scans.map(s=>[s.id,s.company_id]),
    knownFindingHmacs:[...existing].sort()
  };
  // Input lengths and baseline are intentionally checked on both servers.
  const encoded=gzipSync(JSON.stringify(payload),{mtime:0}).toString("base64");
  await db.query("ROLLBACK");
  console.error("READ ONLY | running app scans:",scans.length,
    "| existing host-CVE pairs:",existing.size);
  console.error("Copy the single token line to the Vulners-v2 scanner terminal. Keep the HMAC key secret.");
  process.stdout.write(encoded+"\n");
} catch(err) {
  console.error("Preparation failed:",err.code??err.message);
  await db.query("ROLLBACK").catch(()=>{});
  process.exitCode=1;
} finally {
  await db.end().catch(()=>{});
  key.fill(0);
}
