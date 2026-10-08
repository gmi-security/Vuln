import { notFound, redirect } from "next/navigation";
import CustomerReportingPage from "@/components/CustomerReportingPage";
import { dashboardAccess } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { elasticVulnEnabled } from "@/lib/elastic-vuln-server";

export const dynamic = "force-dynamic";

export default async function ReportingPage({ searchParams }: { searchParams:Promise<{companyId?:string}> }) {
  if (!elasticVulnEnabled()) notFound();
  let access;
  try { access = await dashboardAccess(); }
  catch (error) {
    if (error instanceof DashboardError && error.status === 401) redirect("/login");
    throw error;
  }
  return <CustomerReportingPage canManage={access.canManage} initialCompanyId={(await searchParams).companyId || ""} />;
}
