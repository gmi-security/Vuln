// A failed or incomplete refresh never replaces the last committed generation.
export function createCommittedCache({ load, build, intervalMs = 5000, onPublish = (_entry) => {}, onError = (_error) => {} }) {
  let current = null, flight = null, timer = null, started = false, refreshError = null, checkedAt = null;
  function refresh() {
    if (flight) return flight;
    const work = (async () => {
      const snapshot = await load(current?.snapshot);
      if (snapshot !== current?.snapshot) {
        const view = await build(snapshot, current);
        const prepared = Object.freeze({ snapshot, view });
        onPublish(prepared);
        current = prepared;
      }
      refreshError = null; checkedAt = new Date().toISOString();
      return current;
    })();
    flight = work.catch(error => { refreshError = error instanceof Error ? error.message : String(error); onError(error); throw error; })
      .finally(() => { flight = null; });
    return flight;
  }
  function schedule() {
    if (!started) return;
    timer = setTimeout(() => { timer = null; void refresh().catch(() => {}).finally(schedule); }, intervalMs);
    timer.unref?.();
  }
  return {
    refresh, current: () => current,
    status: () => ({ refreshing: Boolean(flight), refreshError, checkedAt }),
    start() { if (!started) { started = true; schedule(); } },
    stop() { started = false; clearTimeout(timer); timer = null; },
  };
}
