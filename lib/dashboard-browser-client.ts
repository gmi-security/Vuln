// Browser-side dashboard requests. A proxy/restart can return HTML even when
// our route normally returns JSON. Never display that page or its parse error.
class DashboardRequestError extends Error {
  constructor(message: string, readonly retryable = false) { super(message); }
}

export async function readDashboardResponse<T>(response: Response): Promise<T> {
  const path = response.url ? new URL(response.url).pathname : "";
  if (response.status === 401 || path === "/login" || path.startsWith("/api/auth/signin")) {
    throw new DashboardRequestError("Your session expired or access was revoked. Sign in again; your open form has been kept.");
  }
  const retryable = [502, 503, 504].includes(response.status);
  const fallback = retryable
    ? `The dashboard is temporarily unavailable (HTTP ${response.status}). Please retry shortly.`
    : `The dashboard returned an unexpected response (HTTP ${response.status}). Please retry; if it continues, report this status.`;
  const contentType = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() ?? "";
  if (response.redirected || (contentType !== "application/json" && !contentType.endsWith("+json"))) {
    throw new DashboardRequestError(fallback, retryable);
  }
  let data: unknown;
  try { data = await response.json(); }
  catch { throw new DashboardRequestError(fallback, retryable); }
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new DashboardRequestError(fallback, retryable);
  if (!response.ok) {
    const detail = (data as { error?: unknown }).error;
    throw new DashboardRequestError(typeof detail === "string" && detail ? detail : fallback, retryable);
  }
  return data as T;
}

export async function dashboardRequest<T = Record<string, any>>(path: string, init: RequestInit = {}): Promise<T> {
  const readOnly = !init.method || init.method.toUpperCase() === "GET";
  for (let attempt = 0; ; attempt++) {
    try {
      let response: Response;
      try {
        response = await fetch(`/api/elastic-dashboard${path ? `/${path}` : ""}`, {
          ...init, cache: "no-store", headers: { Accept: "application/json", ...init.headers },
          signal: AbortSignal.timeout(20_000),
        });
      } catch {
        throw new DashboardRequestError(readOnly
          ? "Unable to reach the dashboard. Previously loaded results are still shown."
          : "The server did not confirm the request. Your open form has been kept. Check the dashboard before retrying, as the request may have completed.", true);
      }
      return await readDashboardResponse<T>(response);
    } catch (error) {
      // Reads are safe to retry once. Never replay a save/preview/delete without
      // knowing whether the first attempt committed on the server.
      if (readOnly && attempt === 0 && error instanceof DashboardRequestError && error.retryable) {
        await new Promise((resolve) => setTimeout(resolve, 500));
        continue;
      }
      throw error;
    }
  }
}
