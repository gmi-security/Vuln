#!/usr/bin/env python3
"""READ ONLY, bounded Vulners-v2 archive/old feed evidence discovery.

Never starts/stops scans, talks to GMP, mounts volumes, extracts archives,
reads customer reports, or modifies data. Prints aggregate evidence
categories and salted? No: SHA256(path) *labels* only; these are not
authentication or privacy guarantees. No raw paths, filenames, hosts,
CVE IDs, report contents, API credentials, or environment are printed.

This discovers *potential* old artifacts. It cannot prove immutable
scan-time NVT/CVE lineage or customer authorization. Live VT volume
contents are explicitly treated as current feed, NOT historical proof.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from collections import Counter, defaultdict

SCAN_START=dt.datetime(2026, 10, 10, tzinfo=dt.timezone.utc).timestamp()
SCAN_END=dt.datetime(2026, 11, 2, tzinfo=dt.timezone.utc).timestamp()
ROOTS=(
    "/opt/gmi-vuln-api",
    "/opt/greenbone-community-edition",
    "/opt/greenbone",
    "/var/backups",
    "/srv/backups",
    "/mnt/backups",
    "/home/codex/vuln-recovery",
    "/root/vuln-recovery",
)
SKIP_DIRS={"node_modules",".git",".cache","__pycache__","tmp",
           ".npm",".venv","venv"}
ARCHIVE_EXT=(".tar",".tgz",".tar.gz",".tar.xz",".tar.zst",
             ".zip",".7z",".rar",".gz",".bz2",".xz",".zst")
DB_EXT=(".dump",".backup",".sql",".sql.gz",".pgdump")
EXPORT_EXT=(".xml",".nessus",".csv",".nbe",".html",".json")
LABEL=re.compile(r"(greenbone|gvm|gvmd|openvas|nvt|nasl|vt[-_]?data|"
                 r"feed|scan|report|snapshot|archive|backup)",re.I)
FEED=re.compile(r"(vt[-_]?data|nvt|nasl|feed)",re.I)
REPORT=re.compile(r"(report|scan|greenbone|gvmd|openvas|gvm)",re.I)
MAX_FILES_PER_ROOT=100000
MAX_DEPTH=6
MAX_CANDIDATES=2000

def iso(ts):
    return dt.datetime.fromtimestamp(ts,dt.timezone.utc).strftime("%Y-%m-%d")
def category(path):
    n=path.name.lower()
    if n.endswith(DB_EXT): return "database_backup_candidate"
    if n.endswith(ARCHIVE_EXT):
        if FEED.search(n):return "named_feed_archive_candidate"
        if REPORT.search(n):return "named_report_archive_candidate"
        return "other_archive_candidate"
    if n.endswith(EXPORT_EXT) and REPORT.search(n):
        return "named_report_export_candidate"
    return None

def path_label(p):
    return hashlib.sha256(os.fsencode(str(p))).hexdigest()[:14]
def bounded_walk(root, max_depth=MAX_DEPTH, max_files=MAX_FILES_PER_ROOT):
    """No symlink following, no reading file contents, bounded recursion."""
    if not root.is_dir() or root.is_symlink():
        return
    stack=[(root,0)]
    seen=0
    while stack and seen<max_files:
        base,depth=stack.pop()
        try:
            with os.scandir(base) as it:
                entries=list(it)
        except (PermissionError,FileNotFoundError,OSError):
            continue
        for ent in entries:
            seen+=1
            if seen>max_files:break
            try:
                if ent.is_symlink():continue
                if ent.is_dir(follow_symlinks=False):
                    if depth<max_depth and ent.name not in SKIP_DIRS:
                        stack.append((Path(ent.path),depth+1))
                elif ent.is_file(follow_symlinks=False):
                    yield Path(ent.path),ent.stat(follow_symlinks=False)
            except (PermissionError,FileNotFoundError,OSError):
                continue

def cmd(argv):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=12,
                         check=True)
        return p.stdout
    except (OSError,subprocess.TimeoutExpired,subprocess.CalledProcessError):
        return None

def volumes():
    raw=cmd(["docker","volume","ls","--format","{{.Name}}"])
    if raw is None:return []
    out=[]
    for name in raw.splitlines():
        if not name.startswith("greenbone-community-edition_"):continue
        if not (name.endswith("_vt_data_vol") or
                name.endswith("_gvmd_data_vol") or
                name.endswith("_data_objects_vol")):continue
        data=cmd(["docker","volume","inspect",name,"--format","{{json .Mountpoint}}"])
        if data is None:continue
        try:
            path=Path(json.loads(data.strip()))
        except (ValueError,TypeError):
            continue
        if not path.is_dir() or path.is_symlink():continue
        out.append((name.split("_")[-3:] ,path))
    return out

def main():
    print("=== GREENBONE ARCHIVED EVIDENCE DISCOVERY (READ ONLY) ===")
    print("Scan-era reference: 2026-10-10 through 2026-11-01 UTC")
    print("Source classifications: potential candidates ONLY, not immutable proof")
    count=Counter()
    candidate_rows=[]
    visited=0
    for raw in ROOTS:
        root=Path(raw)
        if not root.is_dir():continue
        visited+=1
        for path,st in bounded_walk(root):
            k=category(path)
            if k is None:continue
            count[k]+=1
            if len(candidate_rows)>=MAX_CANDIDATES:continue
            if k=="other_archive_candidate" and not LABEL.search(path.name):
                continue
            candidate_rows.append({
                "category":k,
                "path_id":path_label(path),
                "size_bytes":st.st_size,
                "mtime_utc":iso(st.st_mtime),
                "scan_era_mtime":SCAN_START<=st.st_mtime<SCAN_END
            })
    print("Recognized bounded backup/export directories:",visited)
    print("Candidate types:",json.dumps(dict(sorted(count.items())),sort_keys=True))
    grouped=defaultdict(list)
    for row in candidate_rows:grouped[row["category"]].append(row)
    for k in sorted(grouped):
        print("CATEGORY:",k,"matching_candidates:",len(grouped[k]))
        for row in sorted(grouped[k],key=lambda r:(r["mtime_utc"],r["size_bytes"]),
                          reverse=True)[:8]:
            print("  ",json.dumps(row,sort_keys=True))
    vol=volumes()
    print("Recognized LIVE Greenbone data volumes:",len(vol))
    for _,vpath in vol:
        name=vpath.parent.name.lower()
        if "vt_data" in name: typ="live_vt_feed"
        elif "gvmd_data" in name:typ="live_gvmd_data"
        elif "data_objects" in name:typ="live_data_objects"
        else:typ="unclassified_live_volume"
        stats=Counter()
        mtimes=[]
        for path,st in bounded_walk(vpath,max_depth=8,max_files=150000):
            ext=path.suffix.lower()
            if ext in (".nasl",".inc",".xml",".json",".tar",".gz",".zip"):
                stats[ext]+=1
                if ext in (".nasl",".inc"):mtimes.append(st.st_mtime)
        print("  ",json.dumps({
            "type":typ,"files_by_extension":dict(sorted(stats.items())),
            "oldest_nasl_or_inc_file_mtime_utc":iso(min(mtimes)) if mtimes else None,
            "latest_nasl_or_inc_file_mtime_utc":iso(max(mtimes)) if mtimes else None,
            "is_historical_feed_archive":False
        },sort_keys=True))
    print("NO WRITES. No report contents, secrets or customer targets were read.")
    print("NOTE: file mtimes and current-volume contents cannot independently prove a")
    print("historical feed revision or NVT-to-CVE mapping. Examine candidate archives")
    print("locally under access control only after identifying true scan-era snapshots.")

if __name__=="__main__":
    main()
