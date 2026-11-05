-- GMI historical recovery: immutable source-identity preflight only.
-- Counts, no identifiers/hosts/CVEs. No imports, updates or scans.
-- Run on Vulners-v2 in the gvmd postgres container using psql -X -v ON_ERROR_STOP=1.
-- The 1,172 positive CVE result rows are all tagged done tasks with
-- completed reports, including two locally orphaned scan IDs.
BEGIN READ ONLY;
SET LOCAL statement_timeout='90s';

SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema='public'
  AND table_name IN ('tasks','reports','results','result_nvts','nvts',
                     'report_hosts','report_host_details','targets')
  AND column_name IN ('id','uuid','name','task','report','target',
                      'nvt','nvt_version','result_nvt','date',
                      'severity','host','hostname','hosts',
                      'start_time','end_time','scan_run_status',
                      'run_status','creation_time','modification_time',
                      'cve','value')
ORDER BY table_name,column_name;

WITH tagged AS (
  SELECT t.id AS task_id, t.uuid AS task_uuid
  FROM public.tasks t
  WHERE t.name ~ '^\[SCAN-[0-9]+\]' AND t.run_status=1
),
latest AS (
  SELECT DISTINCT ON (r.task) r.task, r.id AS report_id,
         to_jsonb(r)->>'uuid' AS report_uuid,
         r.end_time
  FROM public.reports r JOIN tagged t ON t.task_id=r.task
  WHERE r.scan_run_status=1 AND r.start_time>0
    AND r.end_time>=r.start_time
  ORDER BY r.task,r.end_time DESC,r.id DESC
),
cve_results AS (
  SELECT t.task_id, t.task_uuid,l.report_id,l.report_uuid,
         r.id AS result_id,
         to_jsonb(r)->>'uuid' AS result_uuid,
         r.nvt_version,r.date AS observed_epoch,
         n.oid,n.creation_time AS nvt_created_epoch,
         n.modification_time AS nvt_modified_epoch,
         l.end_time AS scan_end_epoch
  FROM tagged t
  JOIN latest l ON l.task=t.task_id
  JOIN public.results r ON r.report=l.report_id
  LEFT JOIN public.result_nvts rn ON rn.id=r.result_nvt
  LEFT JOIN public.nvts n
    ON n.oid=COALESCE(NULLIF(btrim(r.nvt),''),
                      NULLIF(btrim(rn.nvt),''))
  WHERE r.severity>0
    AND COALESCE(n.cve ~* 'CVE-[0-9]{4}-[0-9]{4,}', false)
)
SELECT COUNT(*) AS cve_positive_result_rows,
       COUNT(DISTINCT task_id) AS unique_remote_tasks,
       COUNT(DISTINCT report_id) AS unique_completed_reports,
       COUNT(DISTINCT result_id) AS unique_result_rows,
       COUNT(*) FILTER (WHERE NULLIF(btrim(task_uuid),'') IS NOT NULL)
         AS rows_with_task_uuid,
       COUNT(*) FILTER (WHERE NULLIF(btrim(report_uuid),'') IS NOT NULL)
         AS rows_with_report_uuid,
       COUNT(*) FILTER (WHERE NULLIF(btrim(result_uuid),'') IS NOT NULL)
         AS rows_with_result_uuid,
       COUNT(*) FILTER (WHERE NULLIF(btrim(nvt_version),'') IS NOT NULL)
         AS rows_with_result_nvt_version,
       COUNT(*) FILTER (WHERE observed_epoch>0
                            AND observed_epoch<=scan_end_epoch)
         AS rows_with_valid_observed_timestamp,
       COUNT(*) FILTER (WHERE nvt_created_epoch<=scan_end_epoch
                            AND nvt_modified_epoch<=scan_end_epoch)
         AS rows_with_preexisting_nvt_metadata,
       COUNT(*) FILTER (WHERE oid IS NULL)
         AS rows_without_source_nvt
FROM cve_results;

ROLLBACK;
