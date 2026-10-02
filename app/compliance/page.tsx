import { Suspense } from "react";
import VulnCompliancePage from "@/components/VulnCompliancePage";

export default function CompliancePage() {
  return (
    <Suspense>
      <VulnCompliancePage />
    </Suspense>
  );
}
