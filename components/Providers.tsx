"use client";

import { SessionProvider } from "next-auth/react";
import VulnNavigationProvider from "./VulnNavigationProvider";

export default function Providers({ children, initialCapabilities }: { children: React.ReactNode; initialCapabilities?: { enabled: boolean; remediationEnabled: boolean } }) {
  return (
    <SessionProvider refetchOnWindowFocus={false} refetchInterval={5 * 60}>
      <VulnNavigationProvider initialCapabilities={initialCapabilities}>{children}</VulnNavigationProvider>
    </SessionProvider>
  );
}
