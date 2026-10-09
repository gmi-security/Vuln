import { notFound, redirect } from "next/navigation";
import CustomerReportingPage from "@/components/CustomerReportingPage";
import { dashboardAccess } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { elasticVulnEnabled } from "@/lib/elastic-vuln-server";
import { remediationUiEnabled } from "@/lib/remediation-server";
import { remediationView } from "@/lib/remediation-view";

export const dynamic = "force-dynamic";

export default async function RemediationPage({ searchParams }: {
  searchParams: Promise<{ companyId?: string; view?: string }>;
}) {
  if (!elasticVulnEnabled() || !remediationUiEnabled()) notFound();
  let access;
  try { access = await dashboardAccess(); }
  catch (error) {
    if (error instanceof DashboardError && error.status === 401) redirect("/login");
    throw error;
  }
  const params = await searchParams;
  return <CustomerReportingPage canManage={access.canManage}
    initialCompanyId={params.companyId || ""} layout="remediation"
    savedSourceReads={process.env.VULN_SAVED_SOURCE_READS === "true"}
    initialView={remediationView(params.view)} />;
}
