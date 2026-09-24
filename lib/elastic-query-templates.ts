// Last known status per finding as of each UTC day; today's point is as of now.
// Requires a complete baseline/change history and a stable finding event.id.
export const OPEN_VULN_TREND = `FROM logs-crowdstrike.vulnerability-*
| WHERE event.id IS NOT NULL AND @timestamp < NOW()
| EVAL source_status = TO_LOWER(COALESCE(crowdstrike.vulnerability.status, "unknown")),
    change_day = DATE_TRUNC(1 day, @timestamp),
    window_start = DATE_TRUNC(1 day, NOW()) - 29 days,
    time_key = RIGHT(CONCAT("0000000000000000000", TO_STRING(TO_LONG(@timestamp))), 19)
| EVAL state_code = CASE(source_status IN ("open", "reopen"), "1", source_status == "closed", "0", "2"),
    change_day = CASE(change_day < window_start, window_start - 1 day, change_day)
| EVAL status_row = CONCAT(time_key, "|", state_code)
| STATS latest_change = MAX(status_row) BY event.id, change_day
| EVAL offset = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29]
| MV_EXPAND offset
| EVAL day = TO_DATETIME(TO_LONG(DATE_TRUNC(1 day, NOW())) - TO_LONG(offset) * 86400000)
| WHERE change_day <= day
| STATS latest_row = MAX(latest_change) BY event.id, day
| DISSECT latest_row "%{record_time}|%{state}"
| STATS open_vulns = COUNT(*) WHERE state == "1",
    unknown_status = COUNT(*) WHERE state == "2" BY day
| SORT day ASC
| KEEP day, open_vulns, unknown_status`;
