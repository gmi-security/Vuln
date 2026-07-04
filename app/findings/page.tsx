import { Suspense } from "react";
import VulnFindingsPage from "@/components/VulnFindingsPage";

export default function FindingsPage() {
  return (
    <Suspense>
      <VulnFindingsPage />
    </Suspense>
  );
}
