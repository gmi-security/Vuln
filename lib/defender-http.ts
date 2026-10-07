import { getServerSession } from "next-auth";
import { authOptions } from "./auth";
import { DashboardError } from "./elastic-dashboard";
import { dashboardBody, dashboardJson } from "./elastic-dashboard-http";
import { DefenderError } from "./defender-client";
import { ensureHydrated, getCompany } from "./store";
export { dashboardBody as defenderBody, dashboardJson as defenderJson };
export async function defenderAccess(request: Request, mutation = false) {
  const session = await getServerSession(authOptions);
  const user = session?.user as { login?: string; email?: string; orgMember?: boolean } | undefined;
  if (!user || user.orgMember === false) throw new DefenderError("Unauthorized",401);
  if (mutation && request.headers.get("origin") !== new URL(process.env.NEXTAUTH_URL || request.url).origin) throw new DefenderError("Invalid request origin.",403);
  return user.login || user.email || "organization-member";
}
export async function defenderCompany(value: unknown): Promise<string> {
  if (typeof value !== "string" || !value.trim() || value.length > 100) throw new DefenderError("Select an existing customer.");
  await ensureHydrated();
  if (!getCompany(value)) throw new DefenderError("The selected customer does not exist.",404);
  return value;
}
export function defenderFailure(error: unknown) {
  if (error instanceof DefenderError || error instanceof DashboardError) return dashboardJson({ error:error.message },error.status);
  if ((error as { code?: string })?.code === "23505") return dashboardJson({ error:"This Defender tenant is already connected to another customer." },409);
  return dashboardJson({ error:"Defender storage is unavailable. Retry shortly." },503);
}
