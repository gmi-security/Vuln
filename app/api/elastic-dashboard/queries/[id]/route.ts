import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { deleteDashboardTile } from "@/lib/elastic-dashboard-store";

export const dynamic = "force-dynamic";
export async function DELETE(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const { actor } = await dashboardAccess(request, true);
    await deleteDashboardTile((await context.params).id, actor);
    return dashboardJson({ deleted: true });
  } catch (error) { return dashboardFailure(error); }
}
