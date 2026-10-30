// pg-pool observes idle clients only. A checked-out connection can emit an
// error between awaited queries, followed by a less useful transport error.
export function trackPublicationClient(client) {
  let first, released = false;
  const observe = error => { first ??= error; };
  const cleanup = () => { client.off('error', observe); client.off('end', cleanup); };
  client.on('error', observe);
  client.once('end', cleanup);
  return {
    firstError: () => first,
    /** @param {Error} [error] */
    release(error) {
      if (released) return;
      released = true;
      const failure = first ?? error;
      // release restores the pool's observer before ours is detached. Failed
      // clients retain our observer until end, including asynchronous shutdown.
      client.release(failure);
      if (!failure) cleanup();
    },
  };
}

const transientCodes = new Set(['25P03','57014','55P03','40P01','40001','08006','08003',
  '57P01','57P02','57P03','53300','ECONNRESET','ECONNREFUSED','ETIMEDOUT']);
const transientMessages = new Set(['Connection terminated unexpectedly',
  'Connection terminated due to connection timeout','timeout exceeded when trying to connect']);

// Only private preparation belongs here. Never replay an uncertain live COMMIT.
/** @param {()=>Promise<any>} operation
 * @param {(progress:{attempt:number,delayMs:number,code?:string})=>void} [onRetry] */
export async function retryPublicationPreparation(operation, onRetry = () => {}) {
  const delays = [5000,15000,60000];
  for (let attempt = 0; ; attempt++) {
    try { return await operation(); }
    catch (error) {
      if (!transientCodes.has(error?.code) && !transientMessages.has(error?.message)) throw error;
      if (attempt === delays.length) throw Object.assign(
        new Error('Import preparation was interrupted; saved progress will retry automatically.'),
        {code:'platform-publication-deferred', cause:error});
      const delayMs = delays[attempt];
      onRetry({attempt:attempt+1, delayMs, code:error.code});
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }
}
