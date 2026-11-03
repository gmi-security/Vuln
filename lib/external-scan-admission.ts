import { createHash } from 'node:crypto';
import { scannerExactTargetKey } from './scanner-target-scope';

// Pure eligibility policy, NOT a launcher. Every proof must be loaded from a
// trusted source by a future dispatcher and rechecked immediately before it
// atomically claims work. It never creates, starts, or retries a remote task.
export type ExternalDispatchCandidate = {
  companyId: string;
  target: string;
  nessusScanId: number;
  scheduledOccurrenceAt: string;
};
export type NessusRunProof = {
  scanId: number;
  status: string;
  startedAt: string;
  completedAt: string;
  reportId: string;
  coveredTargets: string[];
};
export type CustomerScopeProof = {
  companyId: string;
  enabled: boolean;
  revision: number;
  approvedTargets: string[];
};
export type AuthorizedWindow = {
  companyId: string;
  startsAt: string;
  endsAt: string;
  approved: boolean;
};
export type ScannerCapacityProof = {
  checkedAt: string;
  healthy: boolean;
  activeTaskCount: number;
  queuedTaskCount: number;
  requestedTaskCount: number;
};
export type ExternalAdmissionInput = {
  now: string;
  dispatchEnabled: boolean;
  scannerAdmissionEnabled: boolean;
  candidate: ExternalDispatchCandidate;
  sourceRun: NessusRunProof | null;
  scope: CustomerScopeProof | null;
  window: AuthorizedWindow | null;
  capacity: ScannerCapacityProof | null;
  claimExists: boolean | null;
};
export type ExternalAdmissionDecision = {
  state: 'hold' | 'eligible-for-atomic-claim';
  reason: string;
  dedupKey: string | null;
};
const hold = (reason: string): ExternalAdmissionDecision => ({ state:'hold', reason, dedupKey:null });
const parseTime = (value: string | undefined): number => {
  const parsed = Date.parse(value ?? '');
  return Number.isFinite(parsed) ? parsed : NaN;
};
function normalizedTarget(value: string): string | null {
  try { return scannerExactTargetKey(value); } catch { return null; }
}
export function externalScanDedupKey(candidate: ExternalDispatchCandidate): string | null {
  const key = normalizedTarget(candidate.target);
  if (!key || !Number.isSafeInteger(candidate.nessusScanId) || candidate.nessusScanId < 1 ||
      !candidate.companyId || !Number.isFinite(parseTime(candidate.scheduledOccurrenceAt))) return null;
  return createHash('sha256').update(JSON.stringify([
    candidate.companyId, key, candidate.nessusScanId,
    new Date(candidate.scheduledOccurrenceAt).toISOString(),
  ])).digest('hex');
}
/**
 * Returns ONLY preliminary eligibility for an atomic, durable scanner lease.
 * A caller MUST independently fence/claim the work, re-read live status, and
 * re-evaluate this policy before every remote create/start step. The absence
 * of a persisted claim is NOT itself a lock or a permit to launch a scan.
 */
export function evaluateExternalScanAdmission(input: ExternalAdmissionInput): ExternalAdmissionDecision {
  if (!input.dispatchEnabled || !input.scannerAdmissionEnabled)
    return hold('Dispatch or scanner admission is disabled.');
  const now = parseTime(input.now);
  const occurrence = parseTime(input.candidate.scheduledOccurrenceAt);
  const dedupKey = externalScanDedupKey(input.candidate);
  if (!Number.isFinite(now) || !Number.isFinite(occurrence) || !dedupKey)
    return hold('Invalid candidate or clock.');
  if (!input.scope || !input.scope.enabled || input.scope.companyId !== input.candidate.companyId ||
      !Number.isSafeInteger(input.scope.revision) || input.scope.revision < 1)
    return hold('Missing approved customer scope.');
  const wanted = normalizedTarget(input.candidate.target);
  if (!wanted || !input.scope.approvedTargets.some(t => normalizedTarget(t) === wanted))
    return hold('Target is outside approved exact customer scope.');
  if (!input.window || !input.window.approved || input.window.companyId !== input.candidate.companyId)
    return hold('No approved maintenance window.');
  const start = parseTime(input.window.startsAt), end = parseTime(input.window.endsAt);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end - start > 24*3600*1000 ||
      now < start || now >= end || start < occurrence)
    return hold('Outside a valid approved maintenance window.');
  if (!input.sourceRun || input.sourceRun.scanId !== input.candidate.nessusScanId ||
      input.sourceRun.status.toLowerCase() !== 'completed' || !input.sourceRun.reportId)
    return hold('No completed Nessus source run for this exact schedule.');
  const begun = parseTime(input.sourceRun.startedAt), completed = parseTime(input.sourceRun.completedAt);
  if (!Number.isFinite(begun) || !Number.isFinite(completed) || begun < occurrence ||
      completed < begun || completed > now || completed > end)
    return hold('Nessus run timing cannot be verified for this occurrence.');
  if (!input.sourceRun.coveredTargets.some(t => normalizedTarget(t) === wanted))
    return hold('Nessus report does not attest coverage of the exact approved target.');
  if (!input.capacity || !input.capacity.healthy || !Number.isFinite(parseTime(input.capacity.checkedAt)) ||
      parseTime(input.capacity.checkedAt) > now || now - parseTime(input.capacity.checkedAt) > 30_000 ||
      ![input.capacity.activeTaskCount,input.capacity.queuedTaskCount,input.capacity.requestedTaskCount].every(n => Number.isSafeInteger(n) && n >= 0) ||
      input.capacity.activeTaskCount + input.capacity.queuedTaskCount + input.capacity.requestedTaskCount !== 0)
    return hold('Scanner capacity or fresh health proof unavailable.');
  if (input.claimExists !== false) return hold('Durable deduplication claim absent or already occupied.');
  return { state:'eligible-for-atomic-claim', reason:'Preliminary eligibility; MUST atomically claim and revalidate before any launch.', dedupKey };
}
