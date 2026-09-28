// Last known status per finding at each completed UTC day. report_end is exclusive.
// Requires a complete baseline/change history and a stable finding event.id.
//
// The source scan has a lower @timestamp bound (report_start - 60 days) so it
// doesn't read the index's entire history just to reconstruct a 30-day trend --
// without it, this trips Elasticsearch's circuit breaker ("reused_arrays" /
// "data too large") once the index holds more than a few months of events,
// since every event.id's full history gets scanned before MV_EXPAND. 60 days
// is a safety margin, not a tight bound: CrowdStrike Spotlight re-stamps
// updated_timestamp on every sync pass a finding is still observed (open or
// closed), not only on a status change, so a finding that's still open gets
// re-indexed well inside that window on any realistic (daily+) sync cadence.
// A source with a sync gap longer than 60 days would undercount -- widen this
// if that's ever the case.
export const OPEN_VULN_TREND = `FROM logs-crowdstrike.vulnerability-*
| EVAL report_start = TO_DATETIME("2026-09-23T00:00:00Z"),
    report_end = TO_DATETIME("2026-09-24T00:00:00Z")
| WHERE event.id IS NOT NULL AND @timestamp < report_end AND @timestamp >= report_start - 60 days
| EVAL source_status = TO_LOWER(COALESCE(crowdstrike.vulnerability.status, "unknown")),
    change_day = DATE_TRUNC(1 day, @timestamp),
    time_key = RIGHT(CONCAT("0000000000000000000", TO_STRING(TO_LONG(@timestamp))), 19)
| EVAL state_code = CASE(source_status IN ("open", "reopen"), "1", source_status == "closed", "0", "2"),
    change_day = CASE(change_day < report_start, report_start - 1 day, change_day)
| EVAL status_row = CONCAT(time_key, "|", state_code)
| STATS latest_change = MAX(status_row) BY event.id, change_day, report_start, report_end
| EVAL offset = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30]
| MV_EXPAND offset
| EVAL day = TO_DATETIME(TO_LONG(report_end) - TO_LONG(offset) * 86400000)
| WHERE day >= report_start AND change_day <= day
| STATS latest_row = MAX(latest_change) BY event.id, day
| DISSECT latest_row "%{record_time}|%{state}"
| STATS open_vulns = COUNT(*) WHERE state == "1",
    unknown_status = COUNT(*) WHERE state == "2" BY day
| SORT day ASC
| KEEP day, open_vulns, unknown_status`;
