import VulnCompanyDetailPage from "@/components/VulnCompanyDetailPage";
import { SCAN_PROFILES } from "@/lib/connectors";

export default async function CompanyDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <VulnCompanyDetailPage companyId={id} profiles={SCAN_PROFILES} />;
}
