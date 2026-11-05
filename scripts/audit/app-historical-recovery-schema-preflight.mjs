#!/usr/bin/env node
// READ ONLY: inspect GMI Vuln persistence and historical source statuses
// before designing a NON-WRITING recovery preview.
// Does not print assets, CVEs, customer targets, row IDs or credentials.
// Never updates the application or schedules scans.
import {createRequire} from "node:module";
import {resolve} from "node:path";
import {pathToFileURL} from "node:url";
const requireFromApp=createRequire(resolve(process.cwd(),"package.json"));
const {Client}=requireFromApp("pg");
const {applicationDatabaseSsl}=await import(pathToFileURL(
  resolve(process.cwd(),"lib/db/connection-target.mjs")
).href);
const url=process.env.DATABASE_URL;
if(!url) throw Error("Missing application DATABASE_URL.");
const db=new Client({
  connectionString:url,ssl:applicationDatabaseSsl(url),
  connectionTimeoutMillis:7000,query_timeout:20000
});
const companies=["CO-9150","CO-9153","CO-9156","CO-9159","CO-9162","CO-9165"];
try {
  await db.connect();
  await db.query("BEGIN READ ONLY");
  await db.query("SET LOCAL statement_timeout = '20s'");
  const columnResult=await db.query(
    ["SELECT table_name,column_name,data_type,udt_name,is_nullable,column_default",
     "FROM information_schema.columns WHERE table_schema='public'",
     "AND table_name IN ('app_findings','app_scans','app_companies')",
     "ORDER BY table_name,ordinal_position"].join(" ")
  );
  const columns=columnResult.rows;
  const present=new Set(columns.map(x=>x.table_name));
  if(!present.has("app_findings") || !present.has("app_scans"))
    throw Error("Required app persistence tables missing");
  console.log("\n=== APPLICATION PERSISTENCE COLUMN CONTRACT ===");
  for(const name of ["app_findings","app_scans","app_companies"]) {
    console.log("Table:",name);
    console.table(columns.filter(x=>x.table_name===name).map(x=>({
      column:x.column_name,type:x.udt_name,nullable:x.is_nullable,
      default:x.column_default ?? ""
    })));
  }
  const ix=await db.query(
    ["SELECT tablename,indexname,indexdef FROM pg_indexes",
     "WHERE schemaname='public'",
     "AND tablename IN ('app_findings','app_scans')",
     "ORDER BY tablename,indexname"].join(" ")
  );
  console.log("\n=== PERSISTENCE INDEXES ===");
  console.table(ix.rows);
  const constraints=await db.query(
    ["SELECT conrelid::regclass::text AS table_name,",
     "conname AS constraint_name,contype AS constraint_type,",
     "pg_get_constraintdef(oid) AS definition FROM pg_constraint",
     "WHERE conrelid IN ('public.app_findings'::regclass,",
     "'public.app_scans'::regclass)",
     "ORDER BY table_name,constraint_name"].join(" ")
  );
  console.log("\n=== PERSISTENCE CONSTRAINTS ===");
  console.table(constraints.rows);
  const scans=await db.query(
    ["SELECT company_id,LOWER(status) AS status,COUNT(*)::int AS scan_count",
     "FROM public.app_scans WHERE connector='vulners'",
     "AND company_id=ANY($1::text[]) GROUP BY company_id,LOWER(status)",
     "ORDER BY company_id,status"].join(" "),[companies]
  );
  console.log("\n=== SCAN STATUS INVENTORY (COUNTS ONLY) ===");
  console.table(scans.rows);
  const findings=await db.query(
    ["SELECT company_id,LOWER(status) AS status,COUNT(*)::int AS finding_count",
     "FROM public.app_findings WHERE connector='vulners'",
     "AND company_id=ANY($1::text[]) GROUP BY company_id,LOWER(status)",
     "ORDER BY company_id,status"].join(" "),[companies]
  );
  console.log("\n=== EXISTING FINDING LIFECYCLE (COUNTS ONLY) ===");
  console.table(findings.rows);
  const totalFindings=findings.rows.reduce((sum,x)=>sum+x.finding_count,0);
  const running=scans.rows.filter(x=>x.status==="running")
    .reduce((sum,x)=>sum+x.scan_count,0);
  if(totalFindings!==82 || running!==91)
    throw Error("Baseline changed: expected 82 findings and 91 Running scans");
  await db.query("ROLLBACK");
  console.log("\nBASELINES PASS: 82 stored findings, 91 Running scans.");
  console.log("READ ONLY. Nothing changed.");
} catch(error) {
  console.error("SCHEMA PREFLIGHT FAILED:",error.code??error.message);
  await db.query("ROLLBACK").catch(()=>{});
  process.exitCode=1;
} finally {
  await db.end().catch(()=>{});
}
