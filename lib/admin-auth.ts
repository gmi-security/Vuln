// Shared admin-token gate for the /api/admin/* endpoints (hit by scheduled
// jobs, not a browser session). The token is read from a ?token= query param
// or an x-admin-token header and compared to ADMIN_TOKEN.
//
// Both sides are trimmed before comparison: env values pasted into a dashboard
// (or piped from `openssl rand`) frequently carry a trailing newline/space, and
// a raw !== would reject an otherwise-correct token. Fails closed when
// ADMIN_TOKEN is unset.
export function adminTokenOk(request: Request): boolean {
  const expected = (process.env.ADMIN_TOKEN ?? "").trim();
  if (!expected) return false;
  const provided = (
    new URL(request.url).searchParams.get("token") ??
    request.headers.get("x-admin-token") ??
    ""
  ).trim();
  return provided.length > 0 && provided === expected;
}
