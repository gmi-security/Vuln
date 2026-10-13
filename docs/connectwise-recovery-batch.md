# ConnectWise GET recovery batch (indexes 14–71)

PR #52 remains on production HOLD. This is a standalone operator command, not an application job. Codex does not run it on Vuln-NYC1. The command reads the private `recovery_merge_fenced` database through its named Unix socket in a read-only transaction; it does not update the production or recovery database. It reads `/opt/vuln/.env.local` only to open the existing encrypted ConnectWise connection. It never prints credentials or saves provider response bodies.

The command pins the original 72-item checkpoint and independently recorded index-12/13 evidence hashes, including the successful index-13 retry. It accepts only 58 unique `not_queried` checkpoint entries in positions 14–71. Every run verifies the 96-row uncertain cohort, each pending request's scope hash, the exact Atlas/ConnectWise company and board, the saved account target, and the indexed UUID before any GET. A changed identity, evidence file, account, or cohort stops the run.

Each execution attempt creates `single-N-started.json` exclusively before a GET and `single-N-result.json` plus SHA-256 sidecars after a complete response. A network failure creates `single-N-failure.json`; an incomplete marker, failed evidence write, HTTP 429/401/403/500, ambiguous result, or identity mismatch stops the batch. The command never retries an attempted index automatically. Successful HTTP 200 with zero matches is retained as **unresolved**, not proof that the original creation failed. GETs are sequential, at least 120 seconds apart, with a 15-second absolute HTTPS timeout, 5-second DNS timeout, 2 MiB response cap, public IPv4 DNS pinning, and no redirects. On completion, `batch-14-71-report.json` records classifications and evidence hashes without changing ticket rows.

## Operator commands for Vuln-NYC1, after separate approval to start recovery

Run these in the existing Vuln-NYC1 terminal. They use a separate source checkout and do not change `/opt/vuln` or restart the app. Stop if any prerequisite, hash, preflight, or test fails. Do not replace the pinned hashes or remove attempt markers to make a rerun pass.

```sh
sudo -u codex -H bash -euo pipefail <<'SH'
umask 077
SRC=/home/codex/vuln-recovery/cw-runner-pr52
test ! -e "$SRC"
git clone --branch Vuln2.0 --single-branch https://github.com/gmi-security/Vuln.git "$SRC"
cd "$SRC"
git checkout --detach 5c687c8c3d07019872034a7c715b5aebb28e8a14
test "$(git rev-parse HEAD)" = 5c687c8c3d07019872034a7c715b5aebb28e8a14
node -e 'if (Number(process.versions.node.split(".")[0]) < 22) process.exit(1)'
test -S /home/codex/vuln-recovery/merge-rehearsal-26PA6Y/restore-vR3gUb/socket/.s.PGSQL.55483
test -r /opt/vuln/.env.local
EVIDENCE=/home/codex/vuln-recovery/cw-get-resume-zm1i62th
test -d "$EVIDENCE"
cd "$EVIDENCE"
printf '%s  %s\n' \
  436ffc6eff38a8d82e16128a36831e4781e55db7ae915a3be400bbf44a3d40e9 checkpoint.json \
  c71daa78bb4b253242510afa7851fe86479aca77f7b349f2fafe87358bbd4473 single-12-result.json \
  d0a3457302e400d6d62855e2742d6fd7770c364f1aca8dbb6d59feaecb08fe38 single-13-started.json \
  3f7d9051382fc0a2bb57a4446491135822f98531d5bc80e599b59321b52d6d1d single-13-retry-01-started.json \
  a095869f15911a6ca7dd5cb6f561f1e57ecdcc75e26c8405bb9efa661aa28200 single-13-retry-01-result.json \
  | sha256sum -c -
cd "$SRC"
npm ci --ignore-scripts --no-audit --no-fund
node --test tests/connectwise-recovery-batch.test.mjs
SH
```

The first command only checks local evidence, reads the named recovery clone and connection settings, and reports the next index. It sends no ConnectWise request.

```sh
sudo -u codex -H node /home/codex/vuln-recovery/cw-runner-pr52/scripts/connectwise-recovery-batch.mjs
```

After reviewing a successful preflight and explicitly initiating the GET-only recovery, use the same checkout path:

```sh
sudo -u codex -H node /home/codex/vuln-recovery/cw-runner-pr52/scripts/connectwise-recovery-batch.mjs --execute
```

An interruption after an attempt marker requires evidence review. A rerun will skip only indexes with complete, verified HTTP 200 evidence and will refuse to resend any uncertain attempt or stopped response. HTTP 429 records `Retry-After` but stops; it never starts a retry on its own.

Verify the final report hash and inspect classifications before any application reconciliation decision:

```sh
sudo -u codex -H node -e '
const fs=require("node:fs"),crypto=require("node:crypto");
const dir="/home/codex/vuln-recovery/cw-get-resume-zm1i62th";
const name="batch-14-71-report.json";
const raw=fs.readFileSync(`${dir}/${name}`);
const saved=fs.readFileSync(`${dir}/${name}.sha256`,"utf8").trim();
const actual=crypto.createHash("sha256").update(raw).digest("hex");
if(actual!==saved)throw Error("REPORT_HASH_MISMATCH");
const report=JSON.parse(raw);
if(report.processed!==58||report.records?.length!==58||
   report.totalVerified+report.totalUnresolved!==96)throw Error("REPORT_INCOMPLETE");
console.log(JSON.stringify({processed:report.processed,foundVerified:report.foundVerified,
  notFoundUnresolved:report.notFoundUnresolved,totalVerified:report.totalVerified,
  totalUnresolved:report.totalUnresolved,reportSha256:actual},null,2));
for(const item of report.records)
  console.log(item.index,item.classification,item.ticketId??"unresolved",item.resultSha256);
'
```

The report is evidence for manual reconciliation. It does not update the 96 uncertain database rows or authorize ticket creation, deployment, migrations, PM2 changes, or release of the production HOLD.
