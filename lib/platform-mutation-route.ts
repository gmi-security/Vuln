import { commitPlatformMutation } from "@/lib/store";

// Never rerun a handler: it may already have launched a scan or sent a report.
// A save failure is explicit, so callers are not told their RAM-only edit saved.
export function withDurablePlatformMutation<A extends unknown[]>(handler: (...args: A) => Promise<Response>) {
  return async (...args: A): Promise<Response> => {
    const response = await handler(...args);
    if (response.ok) {
      try { await commitPlatformMutation(); }
      catch (error) {
        console.error("[platform] mutation commit failed:", error instanceof Error ? error.message : error);
        return Response.json({ error: "The platform change could not be confirmed in the database. Check its status before retrying any external action." }, { status: 503, headers: { "Cache-Control": "no-store" } });
      }
    }
    return response;
  };
}
