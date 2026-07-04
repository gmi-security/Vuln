import { Suspense } from "react";
import VulnAttackPathsPage from "@/components/VulnAttackPathsPage";

export default function AttackPathsPage() {
  return (
    <Suspense>
      <VulnAttackPathsPage />
    </Suspense>
  );
}
