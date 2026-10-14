# Gate 3.4 disposable recovery rehearsal — operator procedure

Production remains on HOLD. This document prepares tests; it does not authorize running them. Stop after the read-only preflight until the operator separately approves disposable database creation, fault injection, authority changes, and an isolated application launch. Codex has no server access. Do not use `/opt/vuln`, PM2, a production connection string, provider credentials, or the recovery baseline databases as targets.

The verified **pre-commit** dump is `/home/codex/vuln-recovery/gate3-precommit-ZSHf45/precommit.dump`, SHA-256 `e8a52f902c834f8485ccdb6e2622e9355944d17596d569164d6c7b71512e1a23`. It is only for fault injection. No verified post-commit backup exists yet. First make a new consistent, read-only `pg_dump` of `recovery_merge_fenced`, then independently check its SHA-256 and restore it into a newly named disposable database. Never use the pre-commit dump for the repeat-run test.

The already committed `recovery_merge_fenced` database, `recovery_application`, `gate3_restore_verify`, the pre-commit dump, and the original verified manifest remain unchanged. The new test cluster uses only a private Unix socket at port `55484`, with `listen_addresses=''`, and newly named `gate34_*` databases. The runner refuses a different database name, data directory, socket, PostgreSQL major version, inherited database credentials, unexpected peer session, changed backup/manifest hash, or changed reviewed commit.

## 1. Read-only server preflight — no new database

Run through the existing Vuln-NYC1 terminal as `codex`. This block only inspects the named recovery resources and host capacity. It does not make the missing backup.

```bash
sudo -u codex -H bash -euo pipefail <<'SH'
cd /home/codex/vuln-recovery/cw-runner-pr52
git rev-parse HEAD
git status --short
test -x /usr/lib/postgresql/18/bin/pg_dump
/usr/lib/postgresql/18/bin/pg_dump --version
df -Pk /home/codex/vuln-recovery
free -m
sha256sum /home/codex/vuln-recovery/gate3-precommit-ZSHf45/precommit.dump
sha256sum /home/codex/vuln-recovery/customer-verified-manifest-ygkf_nxc/manifest.json
PGOPTIONS='-c default_transaction_read_only=on' /usr/lib/postgresql/18/bin/psql \
  -X -A -t -P pager=off \
  -h /home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket \
  -p 55483 -U codex -d recovery_merge_fenced \
  -v ON_ERROR_STOP=1 \
  -c "SELECT current_database(),current_setting('server_version_num'),current_setting('data_directory'),current_setting('unix_socket_directories'),current_setting('listen_addresses'),inet_server_addr(),(SELECT mode||':'||epoch||':'||revision FROM app_store_authority WHERE id=1),(SELECT count(*) FROM customer_consolidation_runs);"
SH
```

Stop if the two file hashes differ from the values above and `58825c0cea227b5b874a6fa9f1d3a02d3c288b3194cfd824ef837480f621a0ae`, respectively; the checked-out commit differs from reviewed PR #52; the database is not `recovery_merge_fenced` on PostgreSQL 18 with the named private socket, an empty listen address, a null server address, legacy enforced authority at epoch/revision `1/1`, and exactly one consolidation ledger row; free disk is under **100 GiB**; or available RAM is under **16 GiB**. Record the actual data directory, free space, available RAM, commit, and stdout privately. Do not infer post-commit dump identity from this query alone.

## 2. Approved preparation — consistent backup and disposable cluster

The rest of this document is **proposed for later approval**. After approval, use one shell as `codex` so the exported variables and helper survive between commands. Set the reviewed commit to the exact PR head after pulling it into the separate review checkout, never `/opt/vuln`.

```bash
sudo -u codex -H bash -euo pipefail
cd /home/codex/vuln-recovery/cw-runner-pr52
git fetch origin Vuln2.0
git checkout --detach <REVIEWED_GATE34_COMMIT_SHA>
test "$(git rev-parse HEAD)" = '<REVIEWED_GATE34_COMMIT_SHA>'
test -z "$(git status --porcelain)"
export GATE34_ID="$(openssl rand -hex 6)"
export GATE34_ROOT="/home/codex/vuln-recovery/gate3-4-${GATE34_ID}"
export GATE34_COMMIT="$(git rev-parse HEAD)"
export GATE34_BIN=/usr/lib/postgresql/18/bin
umask 077
mkdir -m 700 "$GATE34_ROOT" "$GATE34_ROOT/socket" "$GATE34_ROOT/evidence"
test "$(realpath "$GATE34_ROOT")" = "$GATE34_ROOT"
test "$(df -Pk "$GATE34_ROOT" | awk 'NR==2 {print $4}')" -ge 104857600
test "$(free -m | awk '/^Mem:/ {print $7}')" -ge 16384
PGOPTIONS='-c default_transaction_read_only=on' "$GATE34_BIN/pg_dump" \
  -h /home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket \
  -p 55483 -U codex -d recovery_merge_fenced \
  --format=custom --serializable-deferrable --no-owner --no-acl \
  --file="$GATE34_ROOT/committed.dump"
export GATE34_COMMITTED_SHA="$(sha256sum "$GATE34_ROOT/committed.dump" | awk '{print $1}')"
test "$GATE34_COMMITTED_SHA" = "$(node -e 'const fs=require("node:fs"),c=require("node:crypto");const h=c.createHash("sha256");fs.createReadStream(process.argv[1]).on("data",x=>h.update(x)).on("end",()=>process.stdout.write(h.digest("hex")))' "$GATE34_ROOT/committed.dump")"
GATE34_ROOT="$GATE34_ROOT" GATE34_COMMITTED_SHA="$GATE34_COMMITTED_SHA" node -e 'const fs=require("node:fs"),e=process.env;fs.writeFileSync(e.GATE34_ROOT+"/evidence/committed-backup.sha256",e.GATE34_COMMITTED_SHA+"  "+e.GATE34_ROOT+"/committed.dump\n",{flag:"wx",mode:0o600})'
sha256sum -c "$GATE34_ROOT/evidence/committed-backup.sha256"
"$GATE34_BIN/pg_restore" --list "$GATE34_ROOT/committed.dump" > "$GATE34_ROOT/evidence/committed-dump-list.txt"
"$GATE34_BIN/initdb" -D "$GATE34_ROOT/data" --encoding=UTF8 --no-locale --auth-local=trust --auth-host=reject
"$GATE34_BIN/pg_ctl" -D "$GATE34_ROOT/data" -l "$GATE34_ROOT/postgresql.log" \
  -o "-k $GATE34_ROOT/socket -h '' -p 55484 -c shared_buffers=128MB -c max_connections=10 -c autovacuum=off" -w start
"$GATE34_BIN/psql" -X -A -t -h "$GATE34_ROOT/socket" -p 55484 -U codex -d postgres \
  -v ON_ERROR_STOP=1 -c "SELECT current_setting('server_version_num'),current_setting('data_directory'),current_setting('listen_addresses'),inet_server_addr();"
```

Stop unless the new cluster reports PostgreSQL 18, the exact new `data` path, an empty listen address, and null `inet_server_addr()`. The `pg_dump` reads `recovery_merge_fenced` but does not write to it. Independently record `GATE34_COMMITTED_SHA` and the original source snapshot hash `2019e6e3f59cb6b706d57447ae28c9d401ec51eea65c438b83c7f0aa2fb63567` before restoring. The runner checks both after restore.

Use the following helper to write the current phase's private config. Each immutable `*.started.json` records the exact config and script SHA-256 values, so later config changes cannot reinterpret an earlier result. Do not put credentials or customer payloads in the config.

```bash
gate34_config() {
  GATE34_MODE="$1" GATE34_DB="$2" GATE34_KIND="$3" GATE34_DUMP="$4" GATE34_SHA="$5" \
  GATE34_BASELINE="${6:-}" GATE34_BASELINE_SHA="${7:-}" node <<'NODE'
const fs=require('node:fs');
const root=process.env.GATE34_ROOT;
const config={root,socket:root+'/socket',database:process.env.GATE34_DB,port:55484,user:'codex',
  expectedCommit:process.env.GATE34_COMMIT,
  sourceDump:{kind:process.env.GATE34_KIND,path:process.env.GATE34_DUMP,sha256:process.env.GATE34_SHA},
  expectedSnapshotSha256:'2019e6e3f59cb6b706d57447ae28c9d401ec51eea65c438b83c7f0aa2fb63567',
  manifestPath:'/home/codex/vuln-recovery/customer-verified-manifest-ygkf_nxc/manifest.json',
  manifestSha256:'58825c0cea227b5b874a6fa9f1d3a02d3c288b3194cfd824ef837480f621a0ae',
  planHash:'cf01d3a95b2f90bfd5d26c937909e8becc9c6feb7bda1e1b6caca9b47a2a1a07'};
if(process.env.GATE34_BASELINE){config.baselineEvidencePath=process.env.GATE34_BASELINE;
  config.baselineEvidenceSha256=process.env.GATE34_BASELINE_SHA;}
fs.writeFileSync(root+'/config.json',JSON.stringify(config,null,2)+'\n',{mode:0o600});
NODE
}
gate34_run() {
  env -i PATH=/usr/bin:/bin HOME=/home/codex \
    node --max-old-space-size=12288 scripts/gate3-disposable-rehearsal.mjs \
      --config "$GATE34_ROOT/config.json" --mode "$1" \
      --evidence-prefix "$GATE34_ROOT/evidence/$2"
}
gate34_restore() {
  case "$1" in
    "gate34_repeat_${GATE34_ID}"|"gate34_restore_${GATE34_ID}"|"gate34_authority_${GATE34_ID}"|"gate34_app_${GATE34_ID}"|"gate34_fault_before_${GATE34_ID}"|"gate34_fault_companies_${GATE34_ID}"|"gate34_fault_scans_${GATE34_ID}"|"gate34_fault_findings_${GATE34_ID}"|"gate34_fault_assets_${GATE34_ID}"|"gate34_fault_tickets_${GATE34_ID}"|"gate34_fault_commit_${GATE34_ID}") ;;
    *) echo 'UNAPPROVED_DISPOSABLE_DATABASE'; return 1 ;;
  esac
  case "$2" in
    "$GATE34_ROOT/committed.dump") expected="$GATE34_COMMITTED_SHA" ;;
    "$GATE34_ROOT/disposable-backup.dump") expected="$GATE34_DISPOSABLE_SHA" ;;
    /home/codex/vuln-recovery/gate3-precommit-ZSHf45/precommit.dump) expected=e8a52f902c834f8485ccdb6e2622e9355944d17596d569164d6c7b71512e1a23 ;;
    *) echo 'UNAPPROVED_BACKUP'; return 1 ;;
  esac
  test "$(sha256sum "$2" | awk '{print $1}')" = "$expected"
  "$GATE34_BIN/createdb" -h "$GATE34_ROOT/socket" -p 55484 -U codex "$1"
  "$GATE34_BIN/pg_restore" --exit-on-error --no-owner --no-privileges \
    -h "$GATE34_ROOT/socket" -p 55484 -U codex -d "$1" "$2"
}
```

## 3. Repeat-run protection — post-commit backup only

```bash
gate34_restore "gate34_repeat_${GATE34_ID}" "$GATE34_ROOT/committed.dump"
gate34_config preflight "gate34_repeat_${GATE34_ID}" postcommit "$GATE34_ROOT/committed.dump" "$GATE34_COMMITTED_SHA"
gate34_run preflight repeat-preflight-01
gate34_run repeat repeat-result-01
```

The preflight must show one existing consolidation ledger row, source customers absent, no orphans, and the pinned committed snapshot digest. `repeat` attempts the original commit path against the **disposable** restored database with the pinned manifest; the changed source snapshot or existing ledger must refuse it. It then requires exact table counts, logical hashes, ledger and authority equality. Any other error or changed evidence stops.

## 4. Fault-injected transaction rollback — pre-commit backup only

Each boundary gets a fresh database. The same reviewed consolidation implementation runs in a serializable transaction. Its selected boundary executes `SELECT 1/0` inside PostgreSQL, requiring SQLSTATE `22012`, then rolls back. A second full fingerprint must equal the first, including every historical ticket/audit table and the absence of a migration ledger row.

```bash
gate34_fault() {
  boundary="$1"
  db="gate34_fault_${boundary}_${GATE34_ID}"
  gate34_restore "$db" /home/codex/vuln-recovery/gate3-precommit-ZSHf45/precommit.dump
  gate34_config "fault-$boundary" "$db" precommit \
    /home/codex/vuln-recovery/gate3-precommit-ZSHf45/precommit.dump \
    e8a52f902c834f8485ccdb6e2622e9355944d17596d569164d6c7b71512e1a23
  gate34_run "fault-$boundary" "fault-$boundary-01"
}
gate34_fault before
gate34_fault companies
gate34_fault scans
gate34_fault findings
gate34_fault assets
gate34_fault tickets
gate34_fault commit
```

Stop at the first failed boundary. Do not retry an uncertain or interrupted test against the same database; preserve its started/failure evidence and restore a **new** disposable database under a new run ID after diagnosis.

## 5. Independent disposable backup and restore

Back up the verified `gate34_repeat_*` test database, not any preserved baseline. Restore the resulting dump into a **separate** `gate34_restore_*` database in the private cluster, then compare the complete schema, table counts and hashes, aliases/lineage, historical tickets/audits, authority, and relationship checks. This is an independent database restore on one server; it does **not** prove off-host disaster recovery.

```bash
PGOPTIONS='-c default_transaction_read_only=on' "$GATE34_BIN/pg_dump" \
  -h "$GATE34_ROOT/socket" -p 55484 -U codex -d "gate34_repeat_${GATE34_ID}" \
  --format=custom --serializable-deferrable --no-owner --no-acl \
  --file="$GATE34_ROOT/disposable-backup.dump"
export GATE34_DISPOSABLE_SHA="$(sha256sum "$GATE34_ROOT/disposable-backup.dump" | awk '{print $1}')"
test "$GATE34_DISPOSABLE_SHA" = "$(node -e 'const fs=require("node:fs"),c=require("node:crypto");const h=c.createHash("sha256");fs.createReadStream(process.argv[1]).on("data",x=>h.update(x)).on("end",()=>process.stdout.write(h.digest("hex")))' "$GATE34_ROOT/disposable-backup.dump")"
gate34_restore "gate34_restore_${GATE34_ID}" "$GATE34_ROOT/disposable-backup.dump"
export GATE34_BASELINE="$GATE34_ROOT/evidence/repeat-result-01.result.json"
export GATE34_BASELINE_SHA="$(sha256sum "$GATE34_BASELINE" | awk '{print $1}')"
gate34_config restore "gate34_restore_${GATE34_ID}" disposable \
  "$GATE34_ROOT/disposable-backup.dump" "$GATE34_DISPOSABLE_SHA" \
  "$GATE34_BASELINE" "$GATE34_BASELINE_SHA"
gate34_run restore restore-verify-01
"$GATE34_BIN/pg_dump" -h "$GATE34_ROOT/socket" -p 55484 -U codex \
  -d "gate34_repeat_${GATE34_ID}" --schema-only --no-owner --no-acl \
  --file="$GATE34_ROOT/evidence/repeat-schema.sql"
"$GATE34_BIN/pg_dump" -h "$GATE34_ROOT/socket" -p 55484 -U codex \
  -d "gate34_restore_${GATE34_ID}" --schema-only --no-owner --no-acl \
  --file="$GATE34_ROOT/evidence/restore-schema.sql"
sha256sum "$GATE34_ROOT/evidence/repeat-schema.sql" "$GATE34_ROOT/evidence/restore-schema.sql"
cmp "$GATE34_ROOT/evidence/repeat-schema.sql" "$GATE34_ROOT/evidence/restore-schema.sql"
```

The runner independently checks every JSON company/folder/scan/finding/asset relationship and any invalid foreign-key state. `cmp` must report no difference; if a dump header or harmless serialization detail differs, stop and review it rather than ignoring the mismatch.

## 6. Forward/reverse authority fencing

```bash
gate34_restore "gate34_authority_${GATE34_ID}" "$GATE34_ROOT/committed.dump"
gate34_config authority "gate34_authority_${GATE34_ID}" postcommit \
  "$GATE34_ROOT/committed.dump" "$GATE34_COMMITTED_SHA"
gate34_run authority authority-transition-01
```

This invokes the repository's `transitionPlatformStore`, `bindPlatformWriter`, `loadPlatformStore`, and `savePlatformStore` with the observed epoch/revision. It tests stale forward/reverse revisions, old writers, repeated transitions, one SQL metadata save and revision advance, reverse preservation of that edit, and full fingerprints at each step. It never calls the generic `DATABASE_URL` transition CLI. An interruption leaves the disposable database for diagnosis; do not infer success from partial logs.

## 7. Isolated application hydration and restart

```bash
gate34_restore "gate34_app_${GATE34_ID}" "$GATE34_ROOT/committed.dump"
gate34_config app "gate34_app_${GATE34_ID}" postcommit \
  "$GATE34_ROOT/committed.dump" "$GATE34_COMMITTED_SHA"
gate34_run app app-preflight-01
```

The `app` command is **only a read-only preflight**; it does not launch the application. Before a launch, independently demonstrate that an unprivileged network namespace is available (`command -v unshare`, `command -v nsenter`, `command -v ip`), `listen_addresses=''` still holds, the review checkout is built for Linux, and the launch environment contains only a socket URL, synthetic local authentication secret, `VULN_PLATFORM_STORE=legacy`, and `VULN_DISABLE_SCHEDULER=true`. No production `.env` may be loaded. The namespace must have **no external interface or route**, only loopback. Do not run PM2 or a report/import/scanner worker. Inspect `lib/store.ts` independent scanner export and Vulners Bridge timers: their provider configurations must remain absent, and outbound vendor access is blocked by the namespace. If any of these checks cannot be independently demonstrated, **do not launch**.

After a separately approved launch, use the private listener inside the namespace and a synthetic, locally signed test session to issue GET-only `/api/health`, `/api/companies`, and customer-scoped `/api/findings?companyId=...&limit=1` requests. Compare GMI and Valor totals, verify every returned row has the requested company, stop the process, restart it against the **same disposable database**, and repeat the GETs. Record startup time, peak RSS, process tree, PostgreSQL sessions, logs, no outbound network, and before/after database fingerprints. Do not use POST/PATCH/PUT/DELETE or any public ingress. Keep this phase **pending** until the namespace and signed test-session procedure have been independently reviewed on Vuln-NYC1.

The following is the exact proposed launch sequence **after** those checks and separate approval. Run it from a root terminal; `setpriv` drops the app to `codex`. Reuse the recorded run ID and review checkout, and validate the literal database name before proceeding. The only network interface in `unshare --net` is loopback; if `unshare`, `setpriv`, `nsenter`, or loopback setup fails, do not start the app elsewhere.

```bash
export GATE34_ID='<RECORDED_RUN_ID>'
export GATE34_ROOT="/home/codex/vuln-recovery/gate3-4-${GATE34_ID}"
export GATE34_REPO=/home/codex/vuln-recovery/cw-runner-pr52
export GATE34_SECRET="$(openssl rand -hex 32)"  # synthetic local-only secret
export GATE34_DB_URL="$(GATE34_ROOT="$GATE34_ROOT" GATE34_ID="$GATE34_ID" node -e 'const e=process.env;process.stdout.write(`postgresql://codex@localhost:55484/gate34_app_${e.GATE34_ID}?host=${encodeURIComponent(e.GATE34_ROOT+"/socket")}`)')"
test "$(realpath "$GATE34_ROOT")" = "$GATE34_ROOT"
test -x /usr/bin/unshare && test -x /usr/bin/nsenter && command -v ip && command -v setpriv
unshare --net -- bash -euc '
    ip link set lo up
    test -z "$(ip -4 route show default)"
    cd "$1"
    exec setpriv --reuid=codex --regid=codex --init-groups env -i \
      PATH=/usr/bin:/bin HOME=/home/codex NODE_ENV=production \
      DATABASE_URL="$2" NEXTAUTH_SECRET="$3" NEXTAUTH_URL=http://127.0.0.1:34173 \
      VULN_PLATFORM_STORE=legacy VULN_DISABLE_SCHEDULER=true npm run build
  ' _ "$GATE34_REPO" "$GATE34_DB_URL" "$GATE34_SECRET"
test -f "$GATE34_REPO/.next/BUILD_ID"
date -u +%FT%TZ > "$GATE34_ROOT/evidence/app-start-time.txt"
umask 077
unshare --net -- bash -euc '
  ip link set lo up
  test -z "$(ip -4 route show default)"
  printf "%s\n" "$$" > "$1/app.pid"
  cd "$2"
  exec setpriv --reuid=codex --regid=codex --init-groups env -i \
    PATH=/usr/bin:/bin HOME=/home/codex NODE_ENV=production \
    DATABASE_URL="$3" NEXTAUTH_SECRET="$4" NEXTAUTH_URL=http://127.0.0.1:34173 \
    VULN_PLATFORM_STORE=legacy VULN_DISABLE_SCHEDULER=true \
    node node_modules/next/dist/bin/next start -H 127.0.0.1 -p 34173
' _ "$GATE34_ROOT" "$GATE34_REPO" "$GATE34_DB_URL" "$GATE34_SECRET" \
  > "$GATE34_ROOT/evidence/app-start.log" 2>&1 &
for attempt in $(seq 1 30); do test -s "$GATE34_ROOT/app.pid" && break; sleep 1; done
test -s "$GATE34_ROOT/app.pid"
export GATE34_APP_PID="$(cat "$GATE34_ROOT/app.pid")"
nsenter -t "$GATE34_APP_PID" -n -- ip -4 addr show
nsenter -t "$GATE34_APP_PID" -n -- ip -4 route show
test -z "$(nsenter -t "$GATE34_APP_PID" -n -- ip -4 route show default)"
tr '\0' '\n' < "/proc/$GATE34_APP_PID/environ" | cut -d= -f1 | sort
```

Inspect the environment **names** only; the list must contain no provider or production configuration. Never print its values. Capture startup time and memory, then use only GET requests inside the namespace. The synthetic token is valid only under the synthetic secret in that process.

```bash
export GATE34_TOKEN="$(cd "$GATE34_REPO" && NEXTAUTH_SECRET="$GATE34_SECRET" node -e 'const {encode}=require("next-auth/jwt");encode({token:{sub:"gate34-local",orgMember:true},secret:process.env.NEXTAUTH_SECRET,maxAge:600}).then(x=>process.stdout.write(x))')"
nsenter -t "$GATE34_APP_PID" -n -- curl --fail --silent --show-error \
  http://127.0.0.1:34173/api/health | node -e 'let s="";process.stdin.on("data",x=>s+=x).on("end",()=>{const x=JSON.parse(s);if(!x.ok||!x.persistence?.dbReachable)process.exit(1);console.log("health=ok")})'
nsenter -t "$GATE34_APP_PID" -n -- curl --fail --silent --show-error \
  --cookie "next-auth.session-token=$GATE34_TOKEN" http://127.0.0.1:34173/api/companies \
  | node -e 'let s="";process.stdin.on("data",x=>s+=x).on("end",()=>{const c=JSON.parse(s).companies;if(!Array.isArray(c)||!c.some(x=>x.id==="CO-229336")||!c.some(x=>x.id==="CO-229438")||c.some(x=>["CO-9150","CO-9153"].includes(x.id)))process.exit(1);console.log("companies="+c.length)})'
for company in CO-229336 CO-229438; do
  nsenter -t "$GATE34_APP_PID" -n -- curl --fail --silent --show-error \
    --cookie "next-auth.session-token=$GATE34_TOKEN" \
    "http://127.0.0.1:34173/api/findings?companyId=$company&limit=1" \
    | GATE34_COMPANY="$company" node -e 'let s="";process.stdin.on("data",x=>s+=x).on("end",()=>{const r=JSON.parse(s);if(!Number.isInteger(r.total)||r.total<1||!Array.isArray(r.findings)||r.findings.some(x=>x.companyId!==process.env.GATE34_COMPANY))process.exit(1);console.log(process.env.GATE34_COMPANY+" findings="+r.total)})'
done
grep -E 'VmRSS|VmHWM' "/proc/$GATE34_APP_PID/status"
ps -o pid,ppid,rss,etime,cmd --forest -p "$GATE34_APP_PID" --ppid "$GATE34_APP_PID"
kill -TERM "$GATE34_APP_PID"
for attempt in $(seq 1 30); do kill -0 "$GATE34_APP_PID" 2>/dev/null || break; sleep 1; done
if kill -0 "$GATE34_APP_PID" 2>/dev/null; then echo 'APP_DID_NOT_STOP'; exit 1; fi
mv "$GATE34_ROOT/app.pid" "$GATE34_ROOT/evidence/app-first.pid"
mv "$GATE34_ROOT/evidence/app-start.log" "$GATE34_ROOT/evidence/app-first.log"
mv "$GATE34_ROOT/evidence/app-start-time.txt" "$GATE34_ROOT/evidence/app-first-start-time.txt"
```

After the process exits, run the read-only fingerprint from the root terminal through `codex` and compare its `result.before` with `app-preflight-01.result.json`:

```bash
cd "$GATE34_REPO"
sudo -u codex -H env -i PATH=/usr/bin:/bin HOME=/home/codex \
  node /home/codex/vuln-recovery/cw-runner-pr52/scripts/gate3-disposable-rehearsal.mjs \
  --config "$GATE34_ROOT/config.json" --mode fingerprint \
  --evidence-prefix "$GATE34_ROOT/evidence/app-after-first-01"
GATE34_ROOT="$GATE34_ROOT" node -e 'const fs=require("node:fs"),r=process.env.GATE34_ROOT;const a=JSON.parse(fs.readFileSync(r+"/evidence/app-preflight-01.result.json")).result.before;const b=JSON.parse(fs.readFileSync(r+"/evidence/app-after-first-01.result.json")).result.before;if(JSON.stringify(a)!==JSON.stringify(b))throw Error("Application GET changed the disposable database")'
```

If a child app process remains or any evidence changed, stop. For the restart, launch the same reviewed command in the same network-only isolation, using a distinct PID and log:

```bash
unshare --net -- bash -euc '
  ip link set lo up
  test -z "$(ip -4 route show default)"
  printf "%s\n" "$$" > "$1/evidence/app-second.pid"
  cd "$2"
  exec setpriv --reuid=codex --regid=codex --init-groups env -i \
    PATH=/usr/bin:/bin HOME=/home/codex NODE_ENV=production \
    DATABASE_URL="$3" NEXTAUTH_SECRET="$4" NEXTAUTH_URL=http://127.0.0.1:34173 \
    VULN_PLATFORM_STORE=legacy VULN_DISABLE_SCHEDULER=true \
    node node_modules/next/dist/bin/next start -H 127.0.0.1 -p 34173
' _ "$GATE34_ROOT" "$GATE34_REPO" "$GATE34_DB_URL" "$GATE34_SECRET" \
  > "$GATE34_ROOT/evidence/app-second.log" 2>&1 &
for attempt in $(seq 1 30); do test -s "$GATE34_ROOT/evidence/app-second.pid" && break; sleep 1; done
test -s "$GATE34_ROOT/evidence/app-second.pid"
export GATE34_APP_PID="$(cat "$GATE34_ROOT/evidence/app-second.pid")"
test -z "$(nsenter -t "$GATE34_APP_PID" -n -- ip -4 route show default)"
```

Repeat the exact three GET checks above with a freshly generated synthetic token, record the same counts and peak RSS, then `kill -TERM "$GATE34_APP_PID"` and confirm its process tree exited. Run the same `fingerprint` command with evidence prefix `app-after-restart-01` and compare it against `app-preflight-01` and `app-after-first-01`. Do not expose this namespace port to the host network. If the full web build or authenticated GET flow fails without a safe fix, keep application hydration/restart marked incomplete; a persistence-only unit test does not satisfy this gate.

## Evidence, stop conditions, and cleanup

Every runner phase writes an exclusive `*.started.json` and either an exclusive `*.result.json` or `*.failure.json` in the private evidence directory, returning the result SHA-256. Repeat, fault and authority modes also create a one-time exclusive `*.lock.json` before any database action; an interrupted attempt must use a fresh disposable database. The files pin the exact PR commit, script hashes, config hash, source dump hash, database identity, schema hash, every table count/hash, snapshot hash, migration ledger, authority epoch/revision, and relationship checks. Preserve terminal output and run `sha256sum "$GATE34_ROOT"/evidence/*.json` after each phase. Do not commit or post private evidence, dumps, customer records, or secrets to PR #52. Summarize only the verified results and limitations in the PR.

If any hash, identity, rollback, relationship, authority or application isolation check fails, stop immediately. Do not mark Gate 3 complete. After evidence is safely retained and the operator approves disposal, stop only the private cluster with `pg_ctl -D "$GATE34_ROOT/data" -m fast -w stop`; confirm no process still uses its socket. Validate `realpath "$GATE34_ROOT"` matches `/home/codex/vuln-recovery/gate3-4-<run-id>` before any later deletion. Never remove a preserved recovery database or backup. Recreate a failed phase from the independently verified source dump in a new run directory; do not retry against an uncertain database.
