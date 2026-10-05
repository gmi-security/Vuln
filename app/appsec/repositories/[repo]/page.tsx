import VulnAppSecRepoPage from "@/components/VulnAppSecRepoPage";

export default async function AppSecRepoPage({
  params,
}: {
  params: Promise<{ repo: string }>;
}) {
  const { repo } = await params;
  return <VulnAppSecRepoPage repository={decodeURIComponent(repo)} />;
}
