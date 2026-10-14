import CustomerAppSecPage from "@/components/CustomerAppSecPage";
export default async function AppSecPage({ searchParams }: { searchParams: Promise<{ companyId?: string | string[] }> }) {
  const { companyId } = await searchParams;
  return <CustomerAppSecPage initialCompanyId={typeof companyId === "string" ? companyId : companyId ? "invalid selection" : undefined} />;
}
