import { Suspense } from "react";
import VulnCoveragePage from "@/components/VulnCoveragePage";

export default function CoveragePage() {
  return (
    <Suspense>
      <VulnCoveragePage />
    </Suspense>
  );
}
