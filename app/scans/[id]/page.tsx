import VulnScanDetailPage from "@/components/VulnScanDetailPage";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <VulnScanDetailPage scanId={id} />;
}
