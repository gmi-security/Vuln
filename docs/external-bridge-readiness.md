# External Greenbone scanning: readiness before controlled rollout

Vulners-v2 successfully completed the approved single-host GMI-SOC-AI pilot on 2026-11-03. The legacy Bridge scheduler is unsafe to re-enable as-is: it couples Nessus-offset jobs with an **entire asset-inventory sweep** and has previously created thousands of Greenbone tasks. Keep `VULNERS_BRIDGE_SCHEDULER_ENABLED=false` and `GMI_SCAN_ADMISSION_ENABLED=false` until a separately reviewed, globally bounded dispatcher has been tested and deployed.

## Read-only admin preview

`GET /api/admin/external-scan-plan` uses the existing `ADMIN_TOKEN` bearer-header check. It joins the Nessus recurrence matrix to **reviewed** Vulners customer routes. It never starts jobs, alters the scanner, or changes scan admission. It shows approved exact host/IP targets rather than imported historical finding assets, the next nominal Nessus +1h offset, and blocked company schedules. Unavailable, duplicated or overlapping routes fail closed. `POST` is intentionally unsupported.

To call this endpoint after the PR has been reviewed, merged **and separately deployed**, use a bearer token in the Authorization header from an approved administration environment. Never put secrets in URLs, chat or shell history. Admin-only output contains sensitive customer scope.

All rows are `review-required`, not launch permissions or proof that Nessus actually completed an occurrence. A schedule by itself is not scan authorization.

## Release gates for a future dispatcher

- Independently validate current customer authorization, exact reviewed routes, permitted maintenance windows and the Nessus run's **actual completed result**. Do not assume a theoretical schedule ran.
- At most one active Greenbone scan globally and one approved host per dispatch. Require a durable deduplication key `(company, target, Nessus occurrence)`. Never automatically retry uncertain scanner create/start results; first check whether an actual remote task exists.
- Do not enable the existing combined Bridge scheduler. Preserve the inventory-sweep block until independently replaced. A deployed GMI application may have additional local runtime differences; reconcile them before deploying.
- Skip missed windows rather than launching an old backlog. Don't rescan a host merely because it appears in imported findings. Don't infer customer approval from DNS or shared IP ownership.
- Validate the deployed API's result pagination, completion, host identity, QoD, report counts, and CVE coverage before resolving old findings or marking an asset clean.
- Test dry-run, rollback and backups, GMI app persistence/restart behavior, scanner concurrency, target impact and endpoint reporting before setting any dispatch flag.

This change is **planning only**. It does not install a new scanner queue, schedule client scans, or modify Vulners-v2. A merge is not a deployment.