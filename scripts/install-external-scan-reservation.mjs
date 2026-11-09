#!/usr/bin/env node
/**
 * Explicit one-shot additive reservation-schema installer, not an app startup
 * migration. Backs up the ENTIRE application database first, verifies backup
 * readability, and installs all three scanner reservation tables atomically.
 *
 * Run on Vuln-NYC1 only when explicitly approved by the operator:
 * node --env-file=.env --env-file=.env.local \
 *   --env-file=.env.production.local \
 *   scripts/install-external-scan-reservation.mjs --apply
 *
 * No scanner, PM2, routing, existing findings or SQL-authority changes.
 */
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, mkdtemp, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import pg from "pg";
import { applicationDatabaseSsl } from "../lib/db/connection-target.mjs";
import { readPlatformAuthority } from "../lib/db/platform-authority.mjs";

export const BACKUP_COMMAND_TIMEOUT_MS = 6 * 60 * 60 * 1000;

const PINNED_PRODUCTION_RELEASE = "23ec37532162c90d00e591e189e2ee62d523353f";
const CHECKS = Object.freeze([
  ["claims","public.external_scan_dispatch_claims"],
  ["slot","public.external_scan_dispatch_slot"],
  ["events","public.external_scan_dispatch_events"],
]);

export function guardFlags(env) {
  for (const key of [
    "VULNERS_BRIDGE_SCHEDULER_ENABLED",
    "GMI_SCAN_ADMISSION_ENABLED",
    "VULN_EXTERNAL_SCAN_DISPATCH_ENABLED",
  ]) {
    if (env[key] === "true") throw Error("STOP: External scanner admission must be disabled.");
  }
}

async function status(db) {
  const result={};
  for (const [name,relation] of CHECKS) {
    const row=(await db.query("SELECT to_regclass($1)::text AS relation",[relation])).rows[0];
    result[name]=row?.relation!==null;
  }
  let occupied=null;
  if (result.slot) {
    const rows=(await db.query(
      "SELECT (claim_key IS NOT NULL) AS occupied FROM public.external_scan_dispatch_slot WHERE slot_id=1"
    )).rows;
    occupied=rows.length===1?rows[0].occupied:null;
  }
  return {tables:result,slotOccupied:occupied};
}
export function complete(value) {return Object.values(value.tables).every(Boolean);}
export function empty(value) {return Object.values(value.tables).every(x=>!x);}

export function pgEnvironment(urlText) {
  const url=new URL(urlText);
  if (!["postgres:","postgresql:"].includes(url.protocol) ||
      !url.pathname || url.pathname.length < 2 || !url.username) throw Error("Invalid application PostgreSQL target.");
  const socket=url.searchParams.get("host");
  const output=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith("PG")));
  Object.assign(output,{
    PGHOST: socket?.startsWith("/")?socket:url.hostname,
    PGPORT:url.port||"5432",
    PGDATABASE:decodeURIComponent(url.pathname.slice(1)),
    PGUSER:decodeURIComponent(url.username),
    PGPASSWORD:decodeURIComponent(url.password),
    PGSSLMODE:socket?.startsWith("/")?"disable":"require",
    PGCONNECT_TIMEOUT:"15",
    PGAPPNAME:"vuln-external-scan-schema-backup",
  });
  return output;
}
function command(command,args,env,log) {
  return new Promise((resolve,reject)=>{
    const child=spawn(command,args,{
      env,stdio:["ignore","ignore",log],timeout:BACKUP_COMMAND_TIMEOUT_MS
    });
    child.once("error",()=>reject(Error("Backup utility unavailable; schema unchanged.")));
    child.once("exit",(code,signal)=>code===0
      ?resolve():reject(Error(command+" failed ("+(signal||code)+"); schema unchanged.")));
  });
}
async function checksum(path) {
  const hash=createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}
async function backupDatabase(url,authority) {
  const parent=process.env.VULN_SCAN_SCHEMA_BACKUP_DIR || "/root/vuln-scan-schema-backups";
  await mkdir(parent,{recursive:true,mode:0o700});
  await chmod(parent,0o700);
  const dir=await mkdtemp(join(parent,"pre-external-scan-"));
  await chmod(dir,0o700);
  const dump=join(dir,"application.dump");
  const logPath=join(dir,"backup.log");
  const fs=await import("node:fs");
  const fd=fs.openSync(logPath,"wx",0o600);
  const env=pgEnvironment(url);
  try{
    console.log("BACKUP_DIRECTORY="+dir);
    console.log("=== CONSISTENT APPLICATION DATABASE BACKUP ===");
    await command("pg_dump",["--format=custom","--compress=1",
      "--no-owner","--no-acl","--file",dump],env,fd);
    await command("pg_restore",["--list",dump],env,fd);
    // Parse/decompress every archive entry, not merely list the TOC.
    await command("pg_restore",["--file=/dev/null",dump],env,fd);
    const bytes=(await stat(dump)).size;
    if(bytes<1024)throw Error("Backup archive unexpectedly small.");
    const sha256=await checksum(dump);
    const manifest={
      kind:"external-scan-reservation-pre-migration",
      createdAt:new Date().toISOString(),authority,dump:"application.dump",
      bytes,sha256,archiveVerified:true,
      limitation:"Archive parsed, NOT restore-tested into a separate database; live writes after snapshot are not included.",
    };
    await writeFile(join(dir,"manifest.json"),JSON.stringify(manifest,null,2)+"\n",{mode:0o600,flag:"wx"});
    return {dir,manifest};
  } finally {
    fs.closeSync(fd);
  }
}
async function install(client) {
  // Only the DDL from the verified deployed release is permitted.
  const repoDir=fileURLToPath(new URL("../",import.meta.url));
  const current=execFileSync("git",["-C",repoDir,"rev-parse","HEAD"],{encoding:"utf8"}).trim();
  if(current!==PINNED_PRODUCTION_RELEASE)
    throw Error("STOP: The application release changed. Re-review migrations.");
  const readPinned = async filename => {
    const local=(await readFile(new URL("../docs/sql/"+filename,import.meta.url),"utf8")).replaceAll("\r\n","\n");
    const trusted=execFileSync("git",["-C",repoDir,"show",PINNED_PRODUCTION_RELEASE+":docs/sql/"+filename],{encoding:"utf8"}).replaceAll("\r\n","\n");
    if(local!==trusted)throw Error("STOP: Deployed migration differs from reviewed Git source.");
    return local;
  };
  const claims=await readPinned("external-scan-dispatch-claims.sql");
  const events=await readPinned("external-scan-dispatch-events.sql");
  let inTxn=false;
  try {
    await client.query("BEGIN");inTxn=true;
    await client.query("SET LOCAL search_path=public");
    await client.query("SET LOCAL lock_timeout='5s'");
    await client.query("SET LOCAL statement_timeout='60s'");
    await client.query("SELECT pg_advisory_xact_lock(20261011,1)");
    const pre=await status(client);
    if(!empty(pre))throw Error("Scanner reservation schema appeared or is partial. No changes.");
    const a=await readPlatformAuthority(client);
    if(a?.mode!=="sql" || a.enforced!==true)
      throw Error("SQL authority changed; no migration applied.");
    // Single transaction: all tables + FK + singleton + index, or none.
    await client.query(claims);
    await client.query(events);
    const after=await status(client);
    if(!complete(after) || after.slotOccupied!==false)
      throw Error("Reservation schema postcondition failed; rollback.");
    const counts=await client.query(
      "SELECT count(*)::int AS count FROM public.external_scan_dispatch_claims"
    );
    if(counts.rows[0].count!==0)
      throw Error("Nonempty new scan-claim table; rollback.");
    await client.query("COMMIT");inTxn=false;
    return after;
  } finally {
    if(inTxn)await client.query("ROLLBACK").catch(()=>{});
  }
}
export async function main(argv=process.argv.slice(2)) {
  if(argv.length!==1 || !["--status","--apply"].includes(argv[0]))
    throw Error("Usage: --status | --apply");
  guardFlags(process.env);
  if(!process.env.DATABASE_URL)throw Error("Application DATABASE_URL is required.");
  const db=new pg.Client({connectionString:process.env.DATABASE_URL,
    ssl:applicationDatabaseSsl(process.env.DATABASE_URL),
    application_name:"vuln-external-scan-reservation-maintenance",
    connectionTimeoutMillis:15000});
  try{
    await db.connect();
    await db.query("BEGIN READ ONLY");
    let before, authority;
    try {
      await db.query("SET LOCAL statement_timeout='15s'");
      before=await status(db);
      authority=await readPlatformAuthority(db);
      await db.query("COMMIT");
    }catch(error){await db.query("ROLLBACK").catch(()=>{});throw error;}
    if(authority?.mode!=="sql" || authority.enforced!==true)
      throw Error("STOP: SQL authority missing or not enforced.");
    console.log(JSON.stringify({schema:before,sqlAuthority:true,epoch:authority.epoch}));
    if(argv[0]==="--status")return;
    if(complete(before)) {
      console.log("PASS: Reservation tables already installed. No SQL changes made.");
      return;
    }
    if(!empty(before)) throw Error("STOP: Partial existing schema; requires independent review.");
    const backup=await backupDatabase(process.env.DATABASE_URL,authority);
    console.log(JSON.stringify({backupVerified:true,backupBytes:backup.manifest.bytes,
      backupDirectory:backup.dir,restoreTested:false}));
    const installed=await install(db);
    console.log(JSON.stringify({migration:"committed",schema:installed,
      backupDirectory:backup.dir,scannerLaunchesEnabled:false}));
  } finally {
    await db.end().catch(()=>{});
  }
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(e=>{
    console.error("STOP:",e.message);
    process.exitCode=2;
  });
}
