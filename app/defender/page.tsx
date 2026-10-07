import DefenderConnectionsPage from "@/components/DefenderConnectionsPage";
export default async function DefenderPage({ searchParams }: { searchParams: Promise<{ companyId?: string }> }) {
  const params = await searchParams;
  return <DefenderConnectionsPage initialCompanyId={typeof params.companyId === "string" ? params.companyId : ""} />;
}
