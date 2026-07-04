import { Suspense } from "react";
import VulnScansPage from "@/components/VulnScansPage";
import { SCAN_PROFILES } from "@/lib/connectors";

export default function ScansPage() {
  return (
    <Suspense>
      <VulnScansPage profiles={SCAN_PROFILES} />
    </Suspense>
  );
}
