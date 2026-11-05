-- GMI Vuln read-only historical Greenbone report and CVE coverage audit
-- Run ONLY against the expected Vulners-v2 gvmd database, as a read-only user.
-- Never treat these counts as approved Nessus scope or ingestion permission.
-- Output omits all target names, IPs, hostnames and individual CVEs.
-- NVT CVE metadata reflects current gvmd state, not immutable scan-time CVE refs.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '90s';

WITH tagged AS (
  SELECT t.id AS task_id,
         substring(t.name FROM '^\[(SCAN-[0-9]+)\]') AS app_scan_id,
         t.run_status,
         lower(regexp_replace(btrim(g.hosts), '\.$', '')) AS target_key
  FROM public.tasks t
  JOIN public.targets g ON g.id = t.target
  WHERE t.name ~ '^\[SCAN-[0-9]+\]'
),
latest_completed AS (
  SELECT DISTINCT ON (r.task) r.task, r.id AS report_id
  FROM public.reports r
  JOIN tagged t ON t.task_id = r.task
  WHERE t.run_status = 1
    AND r.scan_run_status = 1
    AND r.start_time > 0
    AND r.end_time >= r.start_time
  ORDER BY r.task, r.end_time DESC, r.id DESC
),
attested_hosts AS (
  SELECT l.report_id,
         lower(btrim(h.host)) AS host_key,
         BOOL_OR(
           lower(regexp_replace(btrim(h.host), '\.$', '')) = t.target_key
           OR lower(regexp_replace(btrim(h.hostname), '\.$', '')) = t.target_key
           OR EXISTS (
             SELECT 1 FROM public.report_host_details d
             WHERE d.report_host = h.id
               AND lower(d.name) = 'hostname'
               AND lower(regexp_replace(btrim(d.value), '\.$', '')) = t.target_key
           )
         ) AS host_attested
  FROM latest_completed l
  JOIN tagged t ON t.task_id = l.task
  JOIN public.report_hosts h ON h.report = l.report_id
  GROUP BY l.report_id, lower(btrim(h.host))
),
completed_rows AS (
  SELECT t.app_scan_id, t.task_id, t.target_key,
         l.report_id, r.id AS result_id, r.severity,
         lower(btrim(r.host)) AS host_key,
         COALESCE(h.host_attested, FALSE) AS host_attested,
         n.cve AS metadata_cves
  FROM tagged t
  JOIN latest_completed l ON l.task = t.task_id
  JOIN public.results r ON r.report = l.report_id
  LEFT JOIN public.result_nvts rn ON rn.id = r.result_nvt
  LEFT JOIN public.nvts n
    ON n.oid = COALESCE(NULLIF(btrim(r.nvt), ''), NULLIF(btrim(rn.nvt), ''))
  LEFT JOIN attested_hosts h
    ON h.report_id = l.report_id AND h.host_key = lower(btrim(r.host))
),
task_rollup AS (
  SELECT t.app_scan_id,
         COUNT(*) AS tagged_tasks,
         COUNT(*) FILTER (WHERE t.run_status = 1) AS done_tasks,
         COUNT(*) FILTER (WHERE l.report_id IS NOT NULL) AS completed_report_tasks
  FROM tagged t
  LEFT JOIN latest_completed l ON l.task = t.task_id
  GROUP BY t.app_scan_id
),
result_rollup AS (
  SELECT app_scan_id,
         COUNT(*) AS result_rows,
         COUNT(*) FILTER (WHERE severity > 0) AS positive_rows,
         COUNT(*) FILTER (
           WHERE severity > 0 AND COALESCE(metadata_cves ~* 'CVE-[0-9]{4}-[0-9]{4,}', FALSE)
         ) AS positive_with_cve_rows,
         COUNT(*) FILTER (
           WHERE severity > 0 AND COALESCE(metadata_cves ~* 'CVE-[0-9]{4}-[0-9]{4,}', FALSE)
             AND host_attested
         ) AS attested_positive_cve_rows,
         COUNT(*) FILTER (
           WHERE severity >= 7 AND COALESCE(metadata_cves ~* 'CVE-[0-9]{4}-[0-9]{4,}', FALSE)
             AND host_attested
         ) AS attested_high_critical_cve_rows,
         COUNT(*) FILTER (
           WHERE severity > 0 AND NOT COALESCE(metadata_cves ~* 'CVE-[0-9]{4}-[0-9]{4,}', FALSE)
             AND host_attested
         ) AS attested_positive_non_cve_rows
  FROM completed_rows GROUP BY app_scan_id
),
cve_pairs AS (
  SELECT r.app_scan_id,
         COUNT(DISTINCT upper(m.parts[1])) AS distinct_cve_ids,
         COUNT(DISTINCT (r.host_key, upper(m.parts[1]))) AS distinct_report_host_cve_pairs,
         COUNT(DISTINCT (r.target_key, upper(m.parts[1]))) AS distinct_target_cve_pairs
  FROM completed_rows r
  CROSS JOIN LATERAL regexp_matches(
    COALESCE(r.metadata_cves, ''), 'CVE-[0-9]{4}-[0-9]{4,}', 'gi'
  ) AS m(parts)
  WHERE r.severity > 0 AND r.host_attested
  GROUP BY r.app_scan_id
)
SELECT t.app_scan_id, t.tagged_tasks, t.done_tasks,
       t.completed_report_tasks,
       COALESCE(r.result_rows,0) AS result_rows,
       COALESCE(r.positive_rows,0) AS positive_rows,
       COALESCE(r.positive_with_cve_rows,0) AS positive_with_cve_rows,
       COALESCE(r.attested_positive_cve_rows,0) AS attested_positive_cve_rows,
       COALESCE(r.attested_high_critical_cve_rows,0) AS attested_high_critical_cve_rows,
       COALESCE(r.attested_positive_non_cve_rows,0) AS attested_positive_non_cve_rows,
       COALESCE(c.distinct_cve_ids,0) AS distinct_cve_ids,
       COALESCE(c.distinct_report_host_cve_pairs,0) AS distinct_report_host_cve_pairs,
       COALESCE(c.distinct_target_cve_pairs,0) AS distinct_target_cve_pairs
FROM task_rollup t
LEFT JOIN result_rollup r USING (app_scan_id)
LEFT JOIN cve_pairs c USING (app_scan_id)
ORDER BY attested_positive_cve_rows DESC, t.app_scan_id;

ROLLBACK;
