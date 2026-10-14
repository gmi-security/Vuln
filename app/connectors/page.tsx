import VulnConnectorsPage from "@/components/VulnConnectorsPage";
import CustomerConnectorsPage from "@/components/CustomerConnectorsPage";
import { remediationUiEnabled } from "@/lib/remediation-server";
import { elasticVulnEnabled } from "@/lib/elastic-vuln-server";
import { dashboardAccess } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { redirect } from "next/navigation";
import { customerConnectorsHref } from "@/lib/remediation-view";
export const dynamic = "force-dynamic";

export default async function ConnectorsPage({ searchParams }: { searchParams: Promise<{ companyId?: string; view?: string }> }) {
  if (!remediationUiEnabled() || !elasticVulnEnabled()) return <VulnConnectorsPage />;
  try { await dashboardAccess(); }
  catch (error) { if (error instanceof DashboardError && error.status === 401) redirect("/login"); throw error; }
  const params = await searchParams;
  if (params.view === "shared") return <VulnConnectorsPage customerHref={customerConnectorsHref(params.companyId || "")}/>;
  return <CustomerConnectorsPage initialCompanyId={params.companyId || ""}/>;
}
