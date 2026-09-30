// Most-urgent-first priorities in, the one slot to use for a given severity
// out. Critical takes the top slot; High takes the next one down, clamped to
// the last slot if the board only has one priority configured. Shared by
// group-auto-create.ts (a fresh creation) and group-priority-backfill.ts
// (the one-time catch-up for tickets created before this existed) so both
// pick the exact same slot.
export function targetPriorityFor<T extends { id: number }>(severity: "Critical" | "High", priorities: T[]): T | undefined {
  if (!priorities.length) return undefined;
  return severity === "Critical" ? priorities[0] : priorities[Math.min(1, priorities.length - 1)];
}

// Same most-urgent-first slot-picking, generalized to Swath (1 = most
// urgent) for lib/swath-ticket-priority.ts. Swath 1->top slot, Swath
// 2->next, etc., clamped the same way targetPriorityFor is.
export function targetPriorityForSwath<T extends { id: number }>(swath: 1 | 2 | 3 | 4, priorities: T[]): T | undefined {
  if (!priorities.length) return undefined;
  return priorities[Math.min(swath - 1, priorities.length - 1)];
}
