const arizonaDate = new Intl.DateTimeFormat("en-CA", {
  timeZone: "America/Phoenix", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", hourCycle: "h23",
});

// Start once after 21:00 on the Arizona calendar date. No daytime catch-up
// after a missed night; already-running imports can continue past midnight.
export function connectorSyncStart(now = Date.now()): number | null {
  if (!Number.isFinite(now)) return null;
  const parts = Object.fromEntries(arizonaDate.formatToParts(now).map(part => [part.type, part.value]));
  if (Number(parts.hour) < 21) return null;
  return Date.parse(`${parts.year}-${parts.month}-${parts.day}T21:00:00-07:00`);
}
