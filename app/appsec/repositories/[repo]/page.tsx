import { notFound } from "next/navigation";
import VulnAppSecRepoPage from "@/components/VulnAppSecRepoPage";
export default async function AppSecRepoPage({ params, searchParams }: {
  params: Promise<{ repo: string }>; searchParams: Promise<{ companyId?: string | string[] }>;
}) {
  const { repo } = await params;
  let repository: string;
  try { repository = decodeURIComponent(repo); } catch { notFound(); }
  const { companyId } = await searchParams;
  const selected = typeof companyId === "string" ? companyId : companyId ? "invalid selection" : undefined;
  return <VulnAppSecRepoPage key={`${selected ?? "organization"}:${repo}`} repository={repository} companyId={selected} />;
}
