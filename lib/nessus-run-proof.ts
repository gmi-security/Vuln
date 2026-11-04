import { scannerExactTargetKey } from "./scanner-target-scope";
import type { ExternalDispatchCandidate, NessusRunProof } from "./external-scan-admission";

type Row = Record<string, unknown>;
const record = (value: unknown): Row | null =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as Row : null;
const positiveInt = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value > 0;
const unixMs = (value: unknown): number | null =>
  positiveInt(value) ? value * 1000 : null;
const exact = (value: unknown): string | null => {
  if (typeof value !== "string") return null;
  try { return scannerExactTargetKey(value); } catch { return null; }
};
const HISTORY_LIMIT = 100;
const HOST_LIMIT = 100;
const START_DRIFT_MS = 30 * 60_000;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

/**
 * A trusted reader backed by real Nessus GET endpoints.
 * The folder ID must come from a current, reviewed customer Nessus route.
 * No scan creation, launch, stop, export or write actions are allowed.
 */
export type NessusHistoricalEvidenceReader = {
  listScans: (folderId: number) => Promise<unknown>;
  rejectsUnknownHistoryId: (scanId: number, impossibleId: number) => Promise<boolean>;
  scanDetails: (scanId: number, historyId?: number) => Promise<unknown>;
  hostDetails: (scanId: number, hostId: number, historyId: number) => Promise<unknown>;
};

/**
 * Verify one actual Nessus run, rather than using a predicted schedule or
 * previously imported vulnerability findings as evidence.
 *
 * Returns null for unrecognized or ambiguous Nessus API payloads, including
 * responses that do not clearly bind /scans/id?history_id=N to N.
 * A new Nessus version is not implicitly authorized by this parser.
 */
export async function verifyCompletedNessusOccurrence(
  candidate: ExternalDispatchCandidate,
  reviewedFolderId: number,
  reader: NessusHistoricalEvidenceReader,
  now: string = new Date().toISOString(),
): Promise<NessusRunProof | null> {
  const wanted = exact(candidate.target);
  const occurrence = Date.parse(candidate.scheduledOccurrenceAt);
  const current = Date.parse(now);
  if (!wanted || !positiveInt(candidate.nessusScanId) || !positiveInt(reviewedFolderId) ||
      !Number.isFinite(occurrence) || !Number.isFinite(current) ||
      occurrence > current || current - occurrence > 24 * 60 * 60_000)
    return null;

  try {
    const roster = await reader.listScans(reviewedFolderId);
    if (!Array.isArray(roster) || roster.length > 1000 ||
        roster.some(s => !record(s) || !positiveInt(record(s)?.id) || !positiveInt(record(s)?.folderId)) ||
        new Set(roster.map(s => record(s)!.id)).size !== roster.length)
      return null;
    const assigned = roster.filter(s =>
      record(s)!.id === candidate.nessusScanId &&
      record(s)!.folderId === reviewedFolderId);
    if (assigned.length !== 1) return null;

    const ordinary = record(await reader.scanDetails(candidate.nessusScanId));
    if (!Array.isArray(ordinary?.history) ||
        ordinary.history.length < 1 || ordinary.history.length > HISTORY_LIMIT)
      return null;

    const completed = ordinary.history.map(record).filter(h =>
      h && positiveInt(h.history_id) && typeof h.uuid === "string" && UUID.test(h.uuid) &&
      h.status === "completed" && unixMs(h.creation_date) !== null &&
      unixMs(h.creation_date)! >= occurrence &&
      unixMs(h.creation_date)! <= occurrence + START_DRIFT_MS &&
      unixMs(h.creation_date)! <= current);
    if (completed.length !== 1) return null;
    const run = completed[0]!;
    const historyId = run.history_id as number;

    const pinned = record(await reader.scanDetails(candidate.nessusScanId, historyId));
    const info = record(pinned?.info);
    if (!info || info.status !== "completed" ||
        !Array.isArray(pinned?.hosts) || pinned.hosts.length < 1 ||
        pinned.hosts.length > HOST_LIMIT)
      return null;
    // Some Nessus versions omit ID and UUID from pinned scan details.
    // Never infer identity from an HTTP 200 alone. If either ID is absent,
    // require independently confirmed historical selection: the real
    // scanner must reject an impossible ID, and a second existing history
    // must produce a distinct timestamp matching its own history record.
    const pinnedId = pinned?.history_id ?? info.history_id;
    const pinnedUuid = pinned?.uuid ?? info.uuid;
    if (pinnedId !== undefined && pinnedId !== historyId) return null;
    if (pinnedUuid !== undefined && pinnedUuid !== run.uuid) return null;
    if (pinnedId === undefined || pinnedUuid === undefined) {
      const impossibleId = 2147483647;
      if (ordinary.history.some(h => record(h)?.history_id === impossibleId) ||
          await reader.rejectsUnknownHistoryId(candidate.nessusScanId, impossibleId) !== true)
        return null;
      const alternate = ordinary.history.map(record).find(h => h &&
        h.history_id !== historyId && positiveInt(h.history_id) && h.status === "completed" &&
        typeof h.uuid === "string" && UUID.test(h.uuid) && unixMs(h.creation_date) !== null &&
        Math.abs(unixMs(h.creation_date)! - unixMs(run.creation_date)!) > START_DRIFT_MS);
      if (!alternate) return null;
      const alternativeDetail = record(await reader.scanDetails(candidate.nessusScanId, alternate.history_id as number));
      const alternativeInfo = record(alternativeDetail?.info);
      const alternativeStart = unixMs(alternativeInfo?.scan_start);
      const selectedStart = unixMs(info.scan_start);
      if (!alternativeInfo || alternativeInfo.status !== "completed" ||
          alternativeStart === null || selectedStart === null ||
          alternativeStart === selectedStart ||
          Math.abs(alternativeStart - unixMs(alternate.creation_date)!) > START_DRIFT_MS ||
          Math.abs(selectedStart - unixMs(run.creation_date)!) > START_DRIFT_MS)
        return null;
      const alternativeId = alternativeDetail?.history_id ?? alternativeInfo.history_id;
      const alternativeUuid = alternativeDetail?.uuid ?? alternativeInfo.uuid;
      if (alternativeId !== undefined && alternativeId !== alternate.history_id) return null;
      if (alternativeUuid !== undefined && alternativeUuid !== alternate.uuid) return null;
    }

    const began = unixMs(info.scan_start), ended = unixMs(info.scan_end);
    if (began === null || ended === null || began < occurrence ||
        began > occurrence + START_DRIFT_MS || ended < began ||
        ended > current || Math.abs(began - unixMs(run.creation_date)!) > START_DRIFT_MS)
      return null;
    // Tenable omits incomplete_targets for some scan runs. A nonzero or
    // malformed value always blocks. When missing, independently require
    // a completed, time-bounded historical result for EVERY listed host.
    // Missing is never silently interpreted as zero.
    const incomplete = info.incomplete_targets;
    if (incomplete !== undefined && incomplete !== 0) return null;
    const mustProveEachHostFinished = incomplete === undefined;

    const hosts = pinned!.hosts as unknown[];
    if (hosts.some(h => !positiveInt(record(h)?.host_id)) ||
        new Set(hosts.map(h => record(h)!.host_id)).size !== hosts.length)
      return null;
    let matches = 0;
    for (const host of hosts) {
      const hostId = record(host)!.host_id as number;
      const detail = record(await reader.hostDetails(candidate.nessusScanId, hostId, historyId));
      const hostInfo = record(detail?.info);
      if (!hostInfo || !Array.isArray(detail?.vulnerabilities) ||
          (detail?.host_id !== undefined && detail.host_id !== hostId))
        return null;
      if (mustProveEachHostFinished) {
        // The host result MUST belong to the selected completed run, not
        // stale results from the latest/another historical scan. Nessus
        // provides these fields as timestamp strings in the local API.
        if (typeof hostInfo.host_start !== "string" ||
            typeof hostInfo.host_end !== "string") return null;
        const hostBegan = Date.parse(hostInfo.host_start);
        const hostEnded = Date.parse(hostInfo.host_end);
        // A small skew allowance covers timestamp rounding, not a
        // different execution. Invalid or missing timestamps fail closed.
        const skewMs = 120_000;
        if (!Number.isFinite(hostBegan) || !Number.isFinite(hostEnded) ||
            hostBegan > hostEnded || hostBegan < began - skewMs ||
            hostEnded > ended + skewMs || hostEnded > current) return null;
      }
      // A configured hostname in the summary is not scan coverage.
      // ONLY exact aliases returned in PINNED historical host detail count.
      const aliases = [hostInfo["host-fqdn"], hostInfo["host-ip"]];
      if (aliases.some(alias => exact(alias) === wanted)) matches += 1;
    }
    if (matches !== 1) return null;
    return {
      scanId: candidate.nessusScanId,
      status: "completed",
      startedAt: new Date(began).toISOString(),
      completedAt: new Date(ended).toISOString(),
      // Historical UUID is a unique immutable Nessus result identity,
      // not a fabricated Greenbone report number.
      reportId: run.uuid as string,
      coveredTargets: [candidate.target],
    };
  } catch {
    // Uncertain, missing or malformed Nessus responses cannot authorize a
    // Greenbone scan. Do not disclose credentials or partial client scopes.
    return null;
  }
}
