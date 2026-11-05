#!/usr/bin/env python3
"""READ ONLY, metadata-only classification of previously unreported archives.

This script does not open/read any file contents (including archive members),
does not traverse symlinks, touch Greenbone DB/API, and prints no raw
file paths or filenames. Only bounded filesystem stat metadata.

The previous bounded inventory found 26 'other_archive_candidate' files,
but hid all 26 because their filenames lacked NVT/report keywords.
Classify those 26 before deciding whether the source-provenance gap is
resolvable. Filename labels/mtime alone are not reliable feed evidence.
"""
import hashlib
import json
import os
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path

ROOTS=(
  "/opt/gmi-vuln-api","/opt/greenbone-community-edition","/opt/greenbone",
  "/var/backups","/srv/backups","/mnt/backups",
  "/home/codex/vuln-recovery","/root/vuln-recovery",
)
SKIP={".git","node_modules",".cache","__pycache__","tmp",
      ".npm",".venv","venv"}
ARCHIVE_TYPES=(
  ".tar.zst",".tar.gz",".tar.xz",".tgz",".zip",".7z",".rar",
  ".tar",".bz2",".gz",".xz",".zst"
)
SPECIFIC_TYPES=(".dump",".backup",".sql",".sql.gz",".pgdump")
MAX_FILES_PER_ROOT=100000
MAX_DEPTH=6
MAX_PRINT=80

def kind(filename):
  n=filename.lower()
  for ext in SPECIFIC_TYPES:
    if n.endswith(ext):return "database-backup",ext
  for ext in ARCHIVE_TYPES:
    if n.endswith(ext):
      if any(t in n for t in ("feed","nvt","nasl","vt_data")):
        return "named-feed-archive",ext
      if any(t in n for t in ("report","scan","greenbone","gvmd","openvas","gvm")):
        return "named-report-archive",ext
      return "generic-archive",ext
  for ext in (".xml",".nessus",".csv",".nbe",".html",".json"):
    if n.endswith(ext) and any(t in n for t in ("report","scan","greenbone","gvmd","openvas","gvm")):
      return "named-report-export",ext
  return None,None

def iso(seconds):
  return datetime.fromtimestamp(seconds,timezone.utc).strftime("%Y-%m-%d")

def walked(root):
  if not root.is_dir() or root.is_symlink():return
  stack=[(root,0)]
  seen=0
  while stack and seen<MAX_FILES_PER_ROOT:
    folder,depth=stack.pop()
    try:
      with os.scandir(folder) as iterator:
        entries=list(iterator)
    except OSError:
      continue
    for entry in entries:
      seen+=1
      if seen>MAX_FILES_PER_ROOT:break
      try:
        if entry.is_symlink():continue
        if entry.is_dir(follow_symlinks=False):
          if depth<MAX_DEPTH and entry.name not in SKIP:
            stack.append((Path(entry.path),depth+1))
        elif entry.is_file(follow_symlinks=False):
          yield Path(entry.path),entry.stat(follow_symlinks=False)
      except OSError:continue

def main():
  print("=== SCAN-ERA ARCHIVE CANDIDATE METADATA (READ ONLY) ===")
  entries=[]
  by_category=Counter()
  by_suffix=Counter()
  visited=0
  for raw in ROOTS:
    root=Path(raw)
    if not root.is_dir() or root.is_symlink():continue
    visited+=1
    for path,stat in walked(root):
      cat,suffix=kind(path.name)
      if not cat:continue
      by_category[cat]+=1
      by_suffix[suffix]+=1
      if len(entries)>=MAX_PRINT:continue
      entries.append({
        "path_id_sha256_prefix":hashlib.sha256(os.fsencode(str(path))).hexdigest()[:16],
        "class":cat,"extension":suffix,"size_bytes":stat.st_size,
        "mtime_utc":iso(stat.st_mtime),
        "modified_during_oct10_nov01_scan_window":
          1791590400<=stat.st_mtime<1793577600
      })
  print("Recognized search roots:",visited)
  print("Category counts:",json.dumps(dict(sorted(by_category.items())),sort_keys=True))
  print("Extension counts:",json.dumps(dict(sorted(by_suffix.items())),sort_keys=True))
  print("Candidates in scan-era mtime window:",
        sum(1 for x in entries if x["modified_during_oct10_nov01_scan_window"]))
  print("Candidate metadata entries:")
  for x in sorted(entries,key=lambda d:(d["class"],d["mtime_utc"],d["size_bytes"])):
    print(json.dumps(x,sort_keys=True))
  if sum(by_category.values())>len(entries):
    print("TRUNCATED: only first",len(entries),"metadata rows printed")
  print("NO FILE CONTENTS READ. NO CHANGES. No raw filenames or paths emitted.")
  print("A scan-era file mtime is NOT proof of scan-time NVT/CVE attribution.")

if __name__=="__main__":
  main()
