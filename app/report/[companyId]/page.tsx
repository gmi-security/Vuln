import VulnExecReport from "@/components/VulnExecReport";

export default async function ReportPage({
  params,
}: {
  params: Promise<{ companyId: string }>;
}) {
  const { companyId } = await params;
  return <VulnExecReport companyId={companyId} />;
}
