import { RRule } from "rrule";

export type NessusScheduleLike = {
  enabled: boolean;
  starttime: string | null; // Nessus format: "YYYYMMDDTHHmmss"
  timezone: string | null;
  rrules: string | null; // e.g. "FREQ=WEEKLY;INTERVAL=1;BYDAY=SU"
};

// rrule's recurrence math (BYDAY, etc.) runs on a Date's UTC getters, with
// no awareness of IANA zones. To get correct local-calendar-day behavior
// for a zone like "America/Phoenix" the RRULE math below runs in "naive
// local" time -- a Date whose UTC fields hold the zone's wall-clock
// numbers, which is intentionally NOT the real UTC instant -- then the
// result is converted back to a real UTC instant afterward. Converting to
// real UTC *before* handing dtstart to rrule would compute BYDAY against
// the wrong calendar day whenever the instant crosses a UTC date boundary
// relative to the zone's local day.

function zonedPartsAtUtc(
  utcMs: number,
  timeZone: string,
): { y: number; mo: number; d: number; h: number; mi: number; s: number } {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(new Date(utcMs));
  const get = (type: string) => Number(parts.find((p) => p.type === type)?.value ?? 0);
  return { y: get("year"), mo: get("month"), d: get("day"), h: get("hour"), mi: get("minute"), s: get("second") };
}

// Real UTC instant for a given wall-clock time in an IANA zone. Standard
// fixed-point trick: guess the instant assuming the wall-clock numbers
// were already UTC, measure that guess's actual zoned offset, and correct
// -- two passes covers every real-world case, including the hour a DST
// transition lands on.
function zonedTimeToUtcMs(y: number, mo: number, d: number, h: number, mi: number, s: number, timeZone: string): number {
  const targetAsUtcMs = Date.UTC(y, mo - 1, d, h, mi, s);
  let guessMs = targetAsUtcMs;
  for (let i = 0; i < 2; i++) {
    const zoned = zonedPartsAtUtc(guessMs, timeZone);
    const zonedAsUtcMs = Date.UTC(zoned.y, zoned.mo - 1, zoned.d, zoned.h, zoned.mi, zoned.s);
    guessMs += targetAsUtcMs - zonedAsUtcMs;
  }
  return guessMs;
}

function naiveLocalDate(y: number, mo: number, d: number, h: number, mi: number, s: number): Date {
  return new Date(Date.UTC(y, mo - 1, d, h, mi, s));
}

function parseStarttime(starttime: string): { y: number; mo: number; d: number; h: number; mi: number; s: number } {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})$/.exec(starttime);
  if (!m) throw new Error(`Unrecognized Nessus starttime format: ${starttime}`);
  const [, y, mo, d, h, mi, s] = m;
  return { y: Number(y), mo: Number(mo), d: Number(d), h: Number(h), mi: Number(mi), s: Number(s) };
}

// The most recent Nessus occurrence at or before `beforeUtcMs`, as a real
// UTC epoch ms, or null if the schedule is disabled/incomplete or hasn't
// had a first occurrence yet.
export function lastNessusOccurrenceBefore(schedule: NessusScheduleLike, beforeUtcMs: number): number | null {
  if (!schedule.enabled || !schedule.starttime || !schedule.timezone || !schedule.rrules) return null;

  let dtstart: Date;
  try {
    const start = parseStarttime(schedule.starttime);
    dtstart = naiveLocalDate(start.y, start.mo, start.d, start.h, start.mi, start.s);
  } catch {
    return null;
  }

  const beforeLocal = zonedPartsAtUtc(beforeUtcMs, schedule.timezone);
  const beforeNaive = naiveLocalDate(
    beforeLocal.y, beforeLocal.mo, beforeLocal.d, beforeLocal.h, beforeLocal.mi, beforeLocal.s,
  );

  let occurrence: Date | null;
  try {
    const options = RRule.parseString(schedule.rrules);
    const rule = new RRule({ ...options, dtstart });
    occurrence = rule.before(beforeNaive, true);
  } catch {
    return null;
  }
  if (!occurrence) return null;

  return zonedTimeToUtcMs(
    occurrence.getUTCFullYear(), occurrence.getUTCMonth() + 1, occurrence.getUTCDate(),
    occurrence.getUTCHours(), occurrence.getUTCMinutes(), occurrence.getUTCSeconds(),
    schedule.timezone,
  );
}

// The next Nessus occurrence at or after `afterUtcMs`, as a real UTC epoch
// ms -- used by the schedule-matrix page to show an upcoming run time, not
// by the offset trigger itself (which only cares about the past).
export function nextNessusOccurrenceAfter(schedule: NessusScheduleLike, afterUtcMs: number): number | null {
  if (!schedule.enabled || !schedule.starttime || !schedule.timezone || !schedule.rrules) return null;

  let dtstart: Date;
  try {
    const start = parseStarttime(schedule.starttime);
    dtstart = naiveLocalDate(start.y, start.mo, start.d, start.h, start.mi, start.s);
  } catch {
    return null;
  }

  const afterLocal = zonedPartsAtUtc(afterUtcMs, schedule.timezone);
  const afterNaive = naiveLocalDate(afterLocal.y, afterLocal.mo, afterLocal.d, afterLocal.h, afterLocal.mi, afterLocal.s);

  let occurrence: Date | null;
  try {
    const options = RRule.parseString(schedule.rrules);
    const rule = new RRule({ ...options, dtstart });
    occurrence = rule.after(afterNaive, true);
  } catch {
    return null;
  }
  if (!occurrence) return null;

  return zonedTimeToUtcMs(
    occurrence.getUTCFullYear(), occurrence.getUTCMonth() + 1, occurrence.getUTCDate(),
    occurrence.getUTCHours(), occurrence.getUTCMinutes(), occurrence.getUTCSeconds(),
    schedule.timezone,
  );
}
