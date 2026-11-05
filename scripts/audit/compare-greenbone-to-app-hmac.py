#!/usr/bin/env python3
"""GMI historical report recovery: READ-ONLY Greenbone side.

The app prepares a gzip+base64 token containing 91 Running scan-ID/company
associations and HMAC-SHA256 digests of the 82 existing company/target/CVE pairs.
Use the *same private one-time random key* for both scripts via
GMI_AUDIT_HMAC_HEX (64 hex characters). Do not post or commit the key.
Run on Vulners-v2 with docker, psql, Python 3 installed.

Only aggregate counts are printed, never targets, IPs, or CVE identifiers.
No database changes, imports, scan scheduling, API writes, or file writes.
This is historical evidence triage, NOT authorization for rescanning/importing.
"""
import base64
import gzip
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

COMPANIES = ("CO-9150", "CO-9153", "CO-9156",
             "CO-9159", "CO-9162", "CO-9165")
key_hex = os.environ.get("GMI_AUDIT_HMAC_HEX", "")
if not re.fullmatch(r"[0-9a-fA-F]{64}", key_hex):
    sys.exit("Missing private GMI_AUDIT_HMAC_HEX (64 hex digits)")
key = bytes.fromhex(key_hex)

try:
    token = input("Paste HMAC evidence token from Vuln-NYC1: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", token):
        raise ValueError("Malformed evidence token")
    data = gzip.decompress(base64.b64decode(token, validate=True))
    if len(data) > 1_048_576:
        raise ValueError("Token decompression limit exceeded")
    payload = json.loads(data)
    if payload.get("version") != 1 or payload.get("purpose") != (
        "gmi-vulners-historical-host-cve-readonly"):
        raise ValueError("Unexpected evidence schema")
    mapping_rows = payload["scanOwners"]
    digests = payload["knownFindingHmacs"]
    if (len(mapping_rows) != 91 or len(digests) != 82
            or len(set(digests)) != 82):
        raise ValueError("Expected 91 Running scan IDs and 82 existing findings")
    owners = {}
    for entry in mapping_rows:
        if (not isinstance(entry, list) or len(entry) != 2 or
            not isinstance(entry[0], str) or
            not re.fullmatch(r"SCAN-[0-9]+", entry[0]) or
            entry[1] not in COMPANIES or entry[0] in owners):
            raise ValueError("Malformed or duplicate scan/customer association")
        owners[entry[0]] = entry[1]
    if any(not isinstance(d, str) or
           not re.fullmatch(r"[0-9a-f]{64}", d) for d in digests):
        raise ValueError("Malformed HMAC digest")
except Exception as e:
    sys.exit("Evidence token rejected: " + str(e))

# GVM host evidence validation matches report_hosts (same report + reported
# IP) to configured target, directly or using recorded hostname details.
# Using current DNS would not verify historical target resolution.
scan_literals = ",".join("'" + x + "'" for x in sorted(owners))
sql = r"""
BEGIN READ ONLY;
SET LOCAL statement_timeout='90s';
WITH tagged AS (
  SELECT t.id AS task_id,
         substring(t.name FROM '^\[(SCAN-[0-9]+)\]') AS app_scan_id,
         t.target
  FROM public.tasks t
  WHERE t.name ~ '^\[SCAN-[0-9]+\]'
    AND t.run_status = 1
    AND substring(t.name FROM '^\[(SCAN-[0-9]+)\]') IN (__SCAN_IDS__)
),
latest AS (
  SELECT DISTINCT ON (r.task) r.task, r.id AS report_id
  FROM public.reports r
  JOIN tagged t ON t.task_id=r.task
  WHERE r.scan_run_status=1
    AND r.start_time>0 AND r.end_time>=r.start_time
  ORDER BY r.task,r.end_time DESC,r.id DESC
)
SELECT t.app_scan_id, btrim(g.hosts), btrim(r.host),
       upper((m.parts)[1]), r.severity,
       CASE WHEN EXISTS (
         SELECT 1 FROM public.report_hosts h
         WHERE h.report=l.report_id
           AND lower(btrim(h.host))=lower(btrim(r.host))
           AND (
             lower(regexp_replace(btrim(h.host), '\.$', ''))
               =lower(regexp_replace(btrim(g.hosts), '\.$', ''))
             OR lower(regexp_replace(btrim(h.hostname), '\.$', ''))
               =lower(regexp_replace(btrim(g.hosts), '\.$', ''))
             OR EXISTS (
               SELECT 1 FROM public.report_host_details d
               WHERE d.report_host=h.id AND lower(d.name)='hostname'
                 AND lower(regexp_replace(btrim(d.value), '\.$', ''))
                   =lower(regexp_replace(btrim(g.hosts), '\.$', ''))
             )
           )
       ) THEN 1 ELSE 0 END AS host_attested
FROM tagged t
JOIN latest l ON l.task=t.task_id
JOIN public.targets g ON g.id=t.target
JOIN public.results r ON r.report=l.report_id
JOIN public.nvts n ON n.oid=r.nvt
CROSS JOIN LATERAL regexp_matches(
  COALESCE(n.cve,''), 'CVE-[0-9]{4}-[0-9]{4,}', 'gi'
) AS m(parts)
WHERE r.severity>0;
ROLLBACK;
""".replace("__SCAN_IDS__", scan_literals)

try:
    p=subprocess.run([
        "docker","exec","-i","-u","postgres",
        "greenbone-community-edition-pg-gvm-1",
        "psql","-X","-qAt","-v","ON_ERROR_STOP=1",
        "-F","\t","-d","gvmd"
    ], input=sql,text=True,capture_output=True,check=True,timeout=110)
except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
    sys.exit("Read-only gvmd query failed; no comparison produced: " +
             type(e).__name__)

def signature(company, target, cve):
    normalized_target=target.strip().lower().removesuffix(".")
    msg=(company+"\0"+normalized_target+"\0"+cve.strip().upper()).encode()
    return hmac.new(key,msg,hashlib.sha256).hexdigest()

fingerprints=set(digests)
per_company=defaultdict(lambda: {
    "scan_ids":set(), "refs":0, "high_refs":0, "remote":set(),
    "matching":set(), "same_scan_report_host_pairs":set(),
    "max_severity":{}
})
n_refs=0
for line in p.stdout.splitlines():
    vals=line.split("\t")
    if len(vals)!=6:
        sys.exit("Unexpected scanner row shape; no results released")
    app_id,target,reported_host,cve,severity,attested=vals
    if app_id not in owners or not re.fullmatch(r"CVE-\d{4}-\d{4,}",cve):
        sys.exit("Unexpected scanner association or CVE identity")
    if attested!="1":
        sys.exit("Host identity missing historical report attestation; STOP")
    company=owners[app_id]
    sig=signature(company,target,cve)
    rec=per_company[company]
    rec["scan_ids"].add(app_id)
    rec["refs"]+=1
    rec["high_refs"]+=int(float(severity)>=7)
    rec["remote"].add(sig)
    # Highest historical severity for each unique (company,target,CVE)
    # across repeated runs. This is not a current vulnerability severity.
    rec["max_severity"][sig] = max(
        rec["max_severity"].get(sig,0.0), float(severity))
    rec["same_scan_report_host_pairs"].add(
        (app_id,reported_host.strip().lower(),cve))
    if sig in fingerprints:
        rec["matching"].add(sig)
    n_refs+=1
    if n_refs>100000:
        sys.exit("Unexpectedly large report export; stop")

# The remote snapshot should match the 34 local Running scans verified in
# the preceding audit. If it differs, re-baseline, do not quietly continue.
num_scan_ids=len(set().union(*[r["scan_ids"] for r in per_company.values()]))
per_scan_host_cves=sum(len(r["same_scan_report_host_pairs"])
                       for r in per_company.values())
high_count=sum(r["high_refs"] for r in per_company.values())
if (num_scan_ids!=34 or n_refs!=2260 or per_scan_host_cves!=1839
        or high_count!=1070):
    sys.exit("Scanner evidence baseline changed; stop and investigate. "
             "No remote findings imported.")

print("\n=== HISTORICAL REMOTE VS EXISTING APP FINDINGS ===")
print("Remote: 34 scan IDs, 2,260 CVE references, 1,839 "
      "within-scan reported-host/CVE pairs (validated).")
print("Company   scans  CVE refs   unique target/CVE   already in app   not in app")
total_unique=total_existing=total_missing=0
all_remote=set()
for company in COMPANIES:
    r=per_company[company]
    unique=len(r["remote"])
    existing=len(r["matching"])
    missing=unique-existing
    total_unique+=unique
    total_existing+=existing
    total_missing+=missing
    all_remote.update(r["remote"])
    print(f"{company:<10}{len(r['scan_ids']):>5}"
          f"{r['refs']:>10}{unique:>20}"
          f"{existing:>17}{missing:>13}")
print(f"TOTAL     {num_scan_ids:>5}{n_refs:>10}{total_unique:>20}"
      f"{total_existing:>17}{total_missing:>13}")
print("Existing app fingerprints absent from this completed remote evidence:",
      len(fingerprints-all_remote))
print("\n=== ABSENT HISTORICAL CANDIDATES BY MAX OBSERVED SEVERITY ===")
print("Company     critical>=9    high>=7   medium>=4      low>0   total")
counts=[0,0,0,0]
for company in COMPANIES:
    rec=per_company[company]
    missing={
        sig:sev for sig,sev in rec["max_severity"].items()
        if sig not in fingerprints
    }
    groups=[
        sum(1 for sev in missing.values() if sev>=9),
        sum(1 for sev in missing.values() if 7<=sev<9),
        sum(1 for sev in missing.values() if 4<=sev<7),
        sum(1 for sev in missing.values() if 0<sev<4)
    ]
    if sum(groups)!=len(missing):
        sys.exit("Unexpected missing-candidate severity: stop")
    counts=[a+b for a,b in zip(counts,groups)]
    print(f"{company:<11}{groups[0]:>11}{groups[1]:>11}"
          f"{groups[2]:>12}{groups[3]:>11}{len(missing):>8}")
if sum(counts)!=total_missing or total_missing!=913:
    sys.exit("Missing-candidate severity totals differ from audited 913")
print(f"TOTAL      {counts[0]:>11}{counts[1]:>11}"
      f"{counts[2]:>12}{counts[3]:>11}{sum(counts):>8}")
print("Severity reflects the most severe historical result for each"
      " absent company/target/CVE identity, not its current state.")

print("\nREAD ONLY. 'Not in app' are historical comparison candidates,"
      " NOT automatically authorized or currently open vulnerabilities.")
