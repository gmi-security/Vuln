# ConnectWise recovery batch: index 17 and indexes 18–71

PR #52 and production remain on HOLD. This standalone runner uses the named `recovery_merge_fenced` clone in a read-only transaction. It never changes the database or saves ConnectWise response bodies. **This revision disables both execution flags in the operator command.** The retry and continuation commands below are reserved for a later, separately authorized revision. Running them now fails before evidence, database, DNS, or ConnectWise access.

The command pins the original checkpoint, index-12/13 evidence, and the independently verified index-17 attempt and HTTP 429 result. Offline preflight verifies those bytes, sidecars, the 429 classification and `Retry-After: 30`, completed index-14/16 evidence, each request scope, the saved ConnectWise target, and the 96-row recovery cohort. Normal execution cannot skip index 17. The library's retry path requires explicit authorization, verifies the same request in the read-only clone, waits at least five minutes after the original result, writes an exclusive attempt marker before its one GET, and stops on uncertain outcomes. Later GETs use at least five minutes between requests, including restarts, and honor a longer valid `Retry-After`.

## 1. Verify files and run offline preflight

Use the separate recovery checkout. Confirm that the displayed Git SHA matches the reviewed PR commit before relying on the preflight result. These commands do not alter `/opt/vuln`.

```sh
sudo -u codex -H bash -euo pipefail <<'SH'
umask 077
SRC=/home/codex/vuln-recovery/cw-runner-pr52
test -d "$SRC/.git"
cd "$SRC"
git fetch origin Vuln2.0
git checkout --detach origin/Vuln2.0
git rev-parse HEAD
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
  4654271c74d6bc91aef8a61619d5558c6eaf7ab468f2da1a4bddac3f56018ca3 single-17-started.json \
  f42a79528cf6c1568247768426897888d35b7513b46d51202006d957c80c4e38 single-17-result.json \
  | sha256sum -c -
cd "$SRC"
npm ci --ignore-scripts --no-audit --no-fund
node --test tests/connectwise-recovery-batch.test.mjs
node scripts/connectwise-recovery-batch.mjs
SH
```

Preflight should report `nextIndex: 17`, `retryRequired: true`, and `noExternalRequests: true`. Any unexpected result is a stop condition. It reads the private recovery clone and connection settings; it performs no database write or external GET.

## 2. Explicit index-17 retry — disabled pending separate authorization

Reserved command:

```sh
sudo -u codex -H node /home/codex/vuln-recovery/cw-runner-pr52/scripts/connectwise-recovery-batch.mjs --retry-index-17 --authorize-index-17
```

**Do not run it yet.** This revision returns `INDEX_17_RETRY_DISABLED` before any read or GET. A later reviewed change and separate operator authorization are required to unlock it. Never remove or edit the original index-17 files, and never retry an uncertain retry attempt.

## 3. Verify retry evidence offline — after an authorized retry

```sh
sudo -u codex -H node /home/codex/vuln-recovery/cw-runner-pr52/scripts/connectwise-recovery-batch.mjs
```

The preflight must verify `single-17-retry-01-started.json` and `single-17-retry-01-result.json` with their SHA-256 sidecars and report `nextIndex: 18`, `retryRequired: false`. Record independent SHA-256 digests for both new files. An incomplete marker, failure file, another 429, HTTP error, ambiguous response, or identity mismatch is a stop condition.

## 4. Continue indexes 18–71 — disabled pending separate authorization

Reserved command:

```sh
sudo -u codex -H node /home/codex/vuln-recovery/cw-runner-pr52/scripts/connectwise-recovery-batch.mjs --execute
```

**Do not run it yet.** This revision returns `BATCH_EXECUTION_DISABLED` before any read or GET. A later reviewed change and separate operator authorization are required. When unlocked, the runner processes only complete, verified predecessors, one GET at a time. It never automatically retries or skips an uncertain request.

## 5. Review the final reconciliation report — after an authorized batch

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

The report is evidence for manual reconciliation. It does not update ticket rows or authorize ticket creation, deployment, PM2 changes, migrations, scheduler activity, or release of the production HOLD.
