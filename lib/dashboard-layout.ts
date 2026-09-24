export function moveTileIds(ids: string[], from: string, to: string): string[] {
  const start = ids.indexOf(from), end = ids.indexOf(to);
  if (start < 0 || end < 0 || start === end) return ids;
  const moved = [...ids];
  moved.splice(start, 1); moved.splice(end, 0, from);
  return moved;
}

export function applyTileOrder<T extends { id: string }>(tiles: T[], ids: string[]): T[] {
  const positions = new Map(ids.map((id, index) => [id, index]));
  return [...tiles].sort((a, b) => (positions.get(a.id) ?? ids.length) - (positions.get(b.id) ?? ids.length));
}
