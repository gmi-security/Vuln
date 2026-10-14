"use client";

import { SessionProvider } from "next-auth/react";
import VulnNavigationProvider from "./VulnNavigationProvider";

export default function Providers({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider refetchOnWindowFocus={false} refetchInterval={5 * 60}>
      <VulnNavigationProvider>{children}</VulnNavigationProvider>
    </SessionProvider>
  );
}
