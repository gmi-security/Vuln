type PollingOptions = {
  intervalMs: number | (() => number | null);
  timeoutMs?: number;
  onError?: (error: unknown) => void;
};

// A read owns its slot until it settles, including cancellation. Timers are
// scheduled only afterwards, so slow requests cannot build a polling backlog.
export function startPolling(read: (signal: AbortSignal) => Promise<void>, options: PollingOptions) {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let controller: AbortController | undefined;
  let inFlight: Promise<void> | undefined;
  let queued: Promise<void> | undefined;
  function refresh({ afterCurrent = false }: { afterCurrent?: boolean } = {}): Promise<void> {
    if (stopped) return Promise.resolve();
    if (inFlight) {
      // A manual action may have changed data after this read began. Coalesce
      // those requests into one follow-up read instead of discarding them.
      if (!afterCurrent) return inFlight;
      queued ??= inFlight.then(() => { queued = undefined; return refresh(); });
      return queued;
    }
    clearTimeout(timer);
    const current = new AbortController();
    controller = current;
    const timeout = setTimeout(() => current.abort(new DOMException("The read timed out.", "TimeoutError")), options.timeoutMs ?? 20_000);
    inFlight = Promise.resolve().then(() => {
      if (!current.signal.aborted) return read(current.signal);
    }).catch(error => {
      if (!stopped) options.onError?.(error);
    }).finally(() => {
      clearTimeout(timeout);
      // Promise.all can reject before every member settles. Cancel any sibling
      // fetches still using this read's signal before releasing its slot.
      current.abort();
      inFlight = undefined;
      controller = undefined;
      if (stopped) return;
      const interval = typeof options.intervalMs === "function" ? options.intervalMs() : options.intervalMs;
      if (interval !== null) timer = setTimeout(() => { void refresh(); }, interval);
    });
    return inFlight;
  }
  function stop() {
    stopped = true;
    clearTimeout(timer);
    controller?.abort();
  }
  void refresh();
  return { refresh, stop };
}

export type BrowserPoller = ReturnType<typeof startPolling>;
