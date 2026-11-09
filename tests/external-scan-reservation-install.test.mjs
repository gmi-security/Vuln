import test from "node:test";
import assert from "node:assert/strict";
import { guardFlags, pgEnvironment, complete, empty, BACKUP_COMMAND_TIMEOUT_MS, MIN_BACKUP_FREE_BYTES, backupSpaceIsSafe } from "../scripts/install-external-scan-reservation.mjs";

test("large database backup and full archive validation receive six hours each",()=>{
  assert.equal(BACKUP_COMMAND_TIMEOUT_MS,6*60*60*1000);
});
test("backup aborts before exhausting the live host disk reserve",()=>{
  assert.equal(MIN_BACKUP_FREE_BYTES,30*1024**3);
  assert.equal(backupSpaceIsSafe(MIN_BACKUP_FREE_BYTES-1),false);
  assert.equal(backupSpaceIsSafe(MIN_BACKUP_FREE_BYTES),true);
});
test("scanner flags must remain disabled when operator performs schema maintenance",()=>{
  assert.doesNotThrow(()=>guardFlags({}));
  for(const name of [
    "VULNERS_BRIDGE_SCHEDULER_ENABLED",
    "GMI_SCAN_ADMISSION_ENABLED",
    "VULN_EXTERNAL_SCAN_DISPATCH_ENABLED",
  ]){
    assert.throws(()=>guardFlags({[name]:"true"}),/disabled/);
  }
});
test("complete versus empty versus partially installed schema remain distinct",()=>{
  const a={tables:{claims:false,slot:false,events:false}};
  const b={tables:{claims:true,slot:true,events:true}};
  const c={tables:{claims:true,slot:false,events:false}};
  assert.equal(empty(a),true);assert.equal(complete(a),false);
  assert.equal(empty(b),false);assert.equal(complete(b),true);
  assert.equal(empty(c),false);assert.equal(complete(c),false);
});
test("pg_dump receives exact database target via private environment, never a credential argument",()=>{
  const old=process.env.PGPASSWORD;
  process.env.PGPASSWORD="SHOULD_NOT_BE_REUSED";
  try{
    const env=pgEnvironment("postgresql://testuser:p%40ssw0rd@127.0.0.1:5432/testscan");
    assert.equal(env.PGHOST,"127.0.0.1");
    assert.equal(env.PGDATABASE,"testscan");
    assert.equal(env.PGUSER,"testuser");
    assert.equal(env.PGPASSWORD,"p@ssw0rd");
    assert.equal(env.PGSSLMODE,"require");
    assert.equal(process.env.PGPASSWORD,"SHOULD_NOT_BE_REUSED");
  }finally {
    if(old===undefined)delete process.env.PGPASSWORD;
    else process.env.PGPASSWORD=old;
  }
});
test("reject non-postgresql database URL",()=>{
  for(const url of ["https://scanner.example/","sqlite:///tmp/a","postgresql://host/db"]){
    assert.throws(()=>pgEnvironment(url),/PostgreSQL target/);
  }
});
