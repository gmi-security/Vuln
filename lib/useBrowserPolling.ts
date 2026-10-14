"use client";

import { useCallback, useEffect, useRef } from "react";
import { startPolling, type BrowserPoller } from "./browser-polling";

// Changing the read callback (for example a customer filter) aborts the old
// scope. Manual refreshes share the same queue as the scheduled reads.
export function useBrowserPolling(read: (signal: AbortSignal) => Promise<void>, intervalMs: number) {
  const poller = useRef<BrowserPoller | null>(null);
  useEffect(() => {
    const current = startPolling(read, { intervalMs });
    poller.current = current;
    return () => { current.stop(); poller.current = null; };
  }, [read, intervalMs]);
  return useCallback(async () => { await poller.current?.refresh({ afterCurrent: true }); }, []);
}
