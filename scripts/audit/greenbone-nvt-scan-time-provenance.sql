-- READ ONLY: check Greenbone NVT CVE-metadata provenance relative to
-- historical reports. Run only on the verified Vulners-v2 gvmd database.
-- This file never lists IPs, hostnames, CVEs, report IDs or customer names.
-- NVT metadata is mutable; a current valid CVE is not inherently proof
-- that it was assigned to the NVT at the time of a historical scan.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '90s';

WITH latest AS (
  SELECT DISTINCT ON (r.task)
    r.id AS report_id,
    r.end_time AS scan_end_epoch
  FROM public.reports r
  JOIN public.tasks t ON t.id = r.task
  WHERE t.name ~ '^\[SCAN-[0-9]+\]'
    AND t.run_status = 1
    AND r.scan_run_status = 1
    AND r.start_time > 0
    AND r.end_time >= r.start_time
  ORDER BY r.task, r.end_time DESC, r.id DESC
),
positive_cve AS (
  SELECT
    l.scan_end_epoch, r.nvt_version, r.date AS result_epoch,
    n.oid, n.creation_time AS nvt_created_epoch,
    n.modification_time AS nvt_modified_epoch
  FROM latest l
  JOIN public.results r ON r.report=l.report_id
  LEFT JOIN public.result_nvts rn ON rn.id=r.result_nvt
  LEFT JOIN public.nvts n ON n.oid=COALESCE(
    NULLIF(btrim(r.nvt),''),NULLIF(btrim(rn.nvt),'')
  )
  WHERE r.severity > 0
    AND COALESCE(n.cve ~* 'CVE-[0-9]{4}-[0-9]{4,}',false)
)
SELECT
  COUNT(*) AS positive_cve_result_rows,
  COUNT(*) FILTER (WHERE NULLIF(btrim(nvt_version),'') IS NOT NULL)
    AS rows_with_nvt_version,
  COUNT(*) FILTER (WHERE NULLIF(btrim(nvt_version),'') IS NULL)
    AS rows_without_nvt_version,
  COUNT(*) FILTER (WHERE nvt_created_epoch > scan_end_epoch)
    AS nvt_created_after_scan,
  COUNT(*) FILTER (WHERE nvt_modified_epoch > scan_end_epoch)
    AS nvt_modified_after_scan,
  COUNT(*) FILTER (WHERE nvt_modified_epoch <= scan_end_epoch)
    AS nvt_not_modified_since_scan,
  COUNT(*) FILTER (
    WHERE result_epoch > 0 AND result_epoch <= scan_end_epoch
  ) AS rows_with_result_timestamp_within_scan_end,
  to_char(to_timestamp(MIN(scan_end_epoch)) AT TIME ZONE 'UTC',
          'YYYY-MM-DD HH24:MI:SS') AS oldest_report_end_utc,
  to_char(to_timestamp(MAX(scan_end_epoch)) AT TIME ZONE 'UTC',
          'YYYY-MM-DD HH24:MI:SS') AS newest_report_end_utc
FROM positive_cve;

WITH latest AS (
  SELECT DISTINCT ON (r.task)
    r.id AS report_id,
    r.end_time AS scan_end_epoch
  FROM public.reports r
  JOIN public.tasks t ON t.id=r.task
  WHERE t.name ~ '^\[SCAN-[0-9]+\]'
    AND t.run_status=1 AND r.scan_run_status=1
    AND r.start_time>0 AND r.end_time>=r.start_time
  ORDER BY r.task,r.end_time DESC,r.id DESC
)
SELECT
  to_char(to_timestamp(l.scan_end_epoch) AT TIME ZONE 'UTC','YYYY-MM')
    AS report_month_utc,
  COUNT(DISTINCT l.report_id) AS completed_reports_with_positive_cve,
  COUNT(*) AS positive_cve_results
FROM latest l
JOIN public.results r ON r.report=l.report_id
LEFT JOIN public.result_nvts rn ON rn.id=r.result_nvt
LEFT JOIN public.nvts n ON n.oid=COALESCE(
  NULLIF(btrim(r.nvt),''),NULLIF(btrim(rn.nvt),'')
)
WHERE r.severity>0
  AND COALESCE(n.cve ~* 'CVE-[0-9]{4}-[0-9]{4,}',false)
GROUP BY 1 ORDER BY 1;

ROLLBACK;
