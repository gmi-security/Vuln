"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { useSession } from "next-auth/react";
import { startPolling, type BrowserPoller } from "@/lib/browser-polling";
import { readNavigationCapabilities, type NavigationCapabilities } from "@/lib/navigation-capabilities";

const NavigationContext = createContext<{
  capabilities: NavigationCapabilities | null;
  failed: boolean;
  retry: () => void;
  collapsed: boolean;
  setCollapsed: React.Dispatch<React.SetStateAction<boolean>>;
  companyId: string;
  setCompanyId: React.Dispatch<React.SetStateAction<string>>;
} | null>(null);

// UI preferences and feature availability survive client-side page navigation.
// Customer context is only a link convenience; each destination validates scope.
export default function VulnNavigationProvider({ children, initialCapabilities = null }: {
  children: React.ReactNode; initialCapabilities?: NavigationCapabilities | null;
}) {
  const { status, data: session } = useSession();
  const user = session?.user as { login?: string; email?: string; name?: string; role?: string; orgMember?: boolean } | undefined;
  const owner = status === "authenticated" ? JSON.stringify([user?.login, user?.email, user?.name, user?.role, user?.orgMember]) : status;
  const denied = status === "unauthenticated" || user?.orgMember === false;
  const [known, setKnown] = useState<{ owner: string; value: NavigationCapabilities | null }>({ owner, value: initialCapabilities });
  const capabilities = denied ? { enabled: false, remediationEnabled: false } : known.owner === owner ? known.value : initialCapabilities;
  const [failed, setFailed] = useState(false);
  const poller = useRef<BrowserPoller | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  // Scope is kept only in memory and belongs to this authenticated identity.
  // A new account or logout cannot inherit another account's customer links.
  const [company, setCompany] = useState({ owner, value: "" });
  const companyId = !denied && company.owner === owner ? company.value : "";
  const setCompanyId = useCallback<React.Dispatch<React.SetStateAction<string>>>(next => {
    setCompany(previous => ({ owner, value: typeof next === "function" ? next(previous.owner === owner ? previous.value : "") : next }));
  }, [owner]);
  useEffect(() => {
    setFailed(false);
    if (status !== "authenticated" || denied) return;
    let retry = false;
    const current = startPolling(async signal => {
      const response = await fetch("/api/elastic-vulnerabilities/status", { cache: "no-store", signal });
      if (response.status === 401 || response.status === 403) {
        if (!signal.aborted) {
          setKnown({ owner, value: { enabled: false, remediationEnabled: false } });
          setCompany({ owner, value: "" });
        }
        retry = false;
        return;
      }
      const value = await readNavigationCapabilities(response);
      if (!signal.aborted) { setKnown({ owner, value }); setFailed(false); }
      retry = false;
    }, { intervalMs: () => retry ? 30_000 : null, onError: () => { retry = true; setFailed(true); } });
    poller.current = current;
    return () => { current.stop(); poller.current = null; };
  }, [status, owner, denied]);
  return <NavigationContext.Provider value={{ capabilities, failed, retry: () => { void poller.current?.refresh(); }, collapsed, setCollapsed, companyId, setCompanyId }}>{children}</NavigationContext.Provider>;
}

export function useVulnNavigation() {
  const context = useContext(NavigationContext);
  if (!context) throw new Error("Site navigation requires its provider");
  return context;
}
