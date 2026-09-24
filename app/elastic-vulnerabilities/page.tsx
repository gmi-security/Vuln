import { notFound, redirect } from "next/navigation";
import VulnElasticPage from "@/components/VulnElasticPage";
import ElasticQueryDashboard from "@/components/ElasticQueryDashboard";
import { dashboardAccess } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { readDashboard } from "@/lib/elastic-dashboard-store";
import { elasticVulnEnabled, getElasticCoverageView } from "@/lib/elastic-vuln-server";

// Server-side runtime flag: this route can be disabled without rebuilding.
export const dynamic = "force-dynamic";

export default async function ElasticVulnerabilitiesPage() {
  if (!elasticVulnEnabled()) notFound();
  if (process.env.ELASTIC_VULN_SAMPLE_DATA === "true") {
    return <VulnElasticPage view={await getElasticCoverageView()} />;
  }
  let access;
  try { access = await dashboardAccess(); }
  catch (error) {
    if (error instanceof DashboardError && error.status === 401) redirect("/login");
    throw error;
  }
  return <ElasticQueryDashboard initial={await readDashboard(access.canManage)} />;
}
