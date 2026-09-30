// Last known status per finding at each completed UTC week, over the last 5
// weeks. Requires a complete baseline/change history and a stable finding
// event.id.
//
// window_start/day must stay relative (NOW()-based): a literal date here
// silently freezes the trend at whatever day it was authored on.
//
// This used to report daily (30 points) instead of weekly (5 points), with
// an identical query shape otherwise. That tripped Elasticsearch's circuit
// breaker ("reused_arrays" / "data too large") at production data scale --
// twice, within a few KB of the exact 4.4gb limit on two different lookback
// windows, which pointed at MV_EXPAND itself rather than the @timestamp
// bound: MV_EXPAND duplicates every (event.id, change_day) row once per
// trend point before the final STATS collapses it back down, and with
// millions of open findings that's tens of millions of rows at 30 points.
// Weekly cuts the MV_EXPAND fan-out 6x (30 -> 5), which is what actually
// clears the breaker -- narrowing the date window alone did not.
//
// The source scan still keeps a lower @timestamp bound (window_start - 30
// days) so it doesn't read the index's entire history just to reconstruct
// the trend. 30 days is a safety margin, not a tight bound: CrowdStrike
// Spotlight re-stamps updated_timestamp on every sync pass a finding is
// still observed (open or closed), not only on a status change, so a
// finding that's still open gets re-indexed well inside that window on any
// realistic (daily+) sync cadence. A source with a sync gap longer than 30
// days would undercount -- widen this if that's ever the case.
export const OPEN_VULN_TREND = `FROM logs-crowdstrike.vulnerability-*
| EVAL window_start = DATE_TRUNC(1 day, NOW()) - 28 days
| WHERE event.id IS NOT NULL AND @timestamp < NOW() AND @timestamp >= window_start - 30 days
| EVAL source_status = TO_LOWER(COALESCE(crowdstrike.vulnerability.status, "unknown")),
    change_day = DATE_TRUNC(1 day, @timestamp),
    time_key = RIGHT(CONCAT("0000000000000000000", TO_STRING(TO_LONG(@timestamp))), 19)
| EVAL state_code = CASE(source_status IN ("open", "reopen"), "1", source_status == "closed", "0", "2"),
    change_day = CASE(change_day < window_start, window_start - 1 day, change_day)
| EVAL status_row = CONCAT(time_key, "|", state_code)
| STATS latest_change = MAX(status_row) BY event.id, change_day
| EVAL offset = [0,1,2,3,4]
| MV_EXPAND offset
| EVAL day = TO_DATETIME(TO_LONG(DATE_TRUNC(1 day, NOW())) - TO_LONG(offset) * 7 * 86400000)
| WHERE change_day <= day
| STATS latest_row = MAX(latest_change) BY event.id, day
| DISSECT latest_row "%{record_time}|%{state}"
| STATS open_vulns = COUNT(*) WHERE state == "1",
    unknown_status = COUNT(*) WHERE state == "2" BY day
| SORT day ASC
| KEEP day, open_vulns, unknown_status`;
