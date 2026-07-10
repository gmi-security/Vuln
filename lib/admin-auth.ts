import { createHash, timingSafeEqual } from "crypto";

// Shared admin-token gate for the /api/admin/* endpoints (hit by scheduled
// jobs, not a browser session). The token is read from an
// Authorization: Bearer header or an x-admin-token header and compared to
// ADMIN_TOKEN. Query-param tokens are deliberately not accepted: URLs end up
// in access logs, browser history, and Referer headers.
//
// Both sides are trimmed before comparison: env values pasted into a dashboard
// (or piped from `openssl rand`) frequently carry a trailing newline/space, and
// a raw !== would reject an otherwise-correct token. Fails closed when
// ADMIN_TOKEN is unset.
function sha256(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

export function adminTokenOk(request: Request): boolean {
  const expected = (process.env.ADMIN_TOKEN ?? "").trim();
  if (!expected) return false;
  const authorization = request.headers.get("authorization") ?? "";
  const bearer = authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : "";
  const provided = (bearer || request.headers.get("x-admin-token") || "").trim();
  if (!provided) return false;
  // Hash both sides so the buffers are equal length; comparison then runs in
  // constant time regardless of how much of the token matches.
  return timingSafeEqual(sha256(provided), sha256(expected));
}
