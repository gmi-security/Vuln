// Shared response cache for unauthenticated connector health-check routes.
// Each of these probes a real on-prem appliance or vendor API on every hit;
// per proxy.ts's allowlist they're reachable with no session, so without a
// cache an anonymous caller can force unbounded repeat load against real
// infrastructure (in CrowdStrike's case, a live OAuth grant against
// production credentials). Keyed by route name so callers don't collide.
const cache = new Map<string, { body: unknown; status: number; at: number }>();

export async function cachedHealth<T>(
  key: string,
  ttlMs: number,
  compute: () => Promise<{ body: T; status?: number }>,
): Promise<{ body: T; status: number }> {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < ttlMs) {
    return { body: hit.body as T, status: hit.status };
  }
  const { body, status = 200 } = await compute();
  cache.set(key, { body, status, at: Date.now() });
  return { body, status };
}
