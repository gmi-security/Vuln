"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { useSession } from "next-auth/react";

type Capabilities = { enabled: boolean; remediationEnabled: boolean };
const NavigationContext = createContext<{
  capabilities: Capabilities | null;
  failed: boolean;
  retry: () => void;
  collapsed: boolean;
  setCollapsed: React.Dispatch<React.SetStateAction<boolean>>;
  companyId: string;
  setCompanyId: React.Dispatch<React.SetStateAction<string>>;
} | null>(null);

// UI preferences and feature availability survive client-side page navigation.
// Customer context is only a link convenience; each destination validates scope.
export default function VulnNavigationProvider({ children }: { children: React.ReactNode }) {
  const { status } = useSession();
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [collapsed, setCollapsed] = useState(false);
  const [companyId, setCompanyId] = useState("");
  useEffect(() => {
    if (status !== "authenticated") {
      if (status === "unauthenticated") { setCapabilities(null); setCompanyId(""); setFailed(false); }
      return;
    }
    const controller = new AbortController();
    setFailed(false);
    void fetch("/api/elastic-vulnerabilities/status", { cache: "no-store", signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error("Navigation unavailable");
        const data = await response.json();
        if (!controller.signal.aborted) setCapabilities({ enabled: data.enabled === true, remediationEnabled: data.enabled === true && data.remediationEnabled === true });
      }).catch(() => { if (!controller.signal.aborted) setFailed(true); });
    return () => controller.abort();
  }, [status, attempt]);
  return <NavigationContext.Provider value={{ capabilities, failed, retry: () => setAttempt(n => n + 1), collapsed, setCollapsed, companyId, setCompanyId }}>{children}</NavigationContext.Provider>;
}

export function useVulnNavigation() {
  const context = useContext(NavigationContext);
  if (!context) throw new Error("Site navigation requires its provider");
  return context;
}
