import { notFound, redirect } from "next/navigation";
import ElasticQueryDashboard from "@/components/ElasticQueryDashboard";
import { dashboardAccess } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { readDashboard } from "@/lib/elastic-dashboard-store";
import { elasticVulnEnabled } from "@/lib/elastic-vuln-server";

export const dynamic = "force-dynamic";

export default async function ReportingPage() {
  if (!elasticVulnEnabled()) notFound();
  let access;
  try { access = await dashboardAccess(); }
  catch (error) {
    if (error instanceof DashboardError && error.status === 401) redirect("/login");
    throw error;
  }
  return <ElasticQueryDashboard initial={await readDashboard(access.canManage)} />;
}
