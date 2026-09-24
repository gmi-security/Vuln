import { notFound } from "next/navigation";
import VulnElasticPage from "@/components/VulnElasticPage";
import { elasticVulnEnabled, getElasticCoverageView } from "@/lib/elastic-vuln-server";

// Server-side runtime flag: this route can be disabled without rebuilding.
export const dynamic = "force-dynamic";

export default async function ElasticVulnerabilitiesPage() {
  if (!elasticVulnEnabled()) notFound();
  return <VulnElasticPage view={await getElasticCoverageView()} />;
}
