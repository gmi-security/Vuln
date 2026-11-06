import { createHash } from "node:crypto";
import { scannerExactTargetKey } from "./scanner-target-scope";
import type { ExternalDispatchCandidate, NessusRunProof } from "./external-scan-admission";

/**
 * Strict shape for a FUTURE scanner-side exhaustive GMP report adapter.
 * No current Bridge endpoint supplies this attestation. Do not accept the
 * legacy /scans/{id}/findings response as equivalent to host coverage.
 *
 * The trusted adapter must check task ownership and report UUID directly
 * against gvmd, consume ALL pages including zero-CVE host results, and
 * derive all booleans below from those records (never from caller input).
 *
 * This module is a PURE parser. It cannot start scans, mark old app records
 * complete, mutate reservations, or declare an unverified scan successful.
 */
type Row = Record<string, unknown>;
const obj = (v:unknown): Row | null =>
  v !== null && typeof v === "object" && !Array.isArray(v) ? v as Row : null;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const JOB_ID = /^[A-Za-z0-9_-]{1,128}$/;
const positiveTime = (value:unknown):number | null => {
  if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d/.test(value))
    return null;
  const ts=Date.parse(value);
  return Number.isFinite(ts) && ts>0 ? ts : null;
};
const canonical = (value:unknown):string | null => {
  if (typeof value !== "string") return null;
  try {return scannerExactTargetKey(value);}catch{return null;}
};

export type GreenboneTerminalProof = {
  taskId: string;
  reportId: string;
  target: string;
  nessusScanId: number;
  nessusRunId: string;
  greenboneStartedAt: string;
  greenboneCompletedAt: string;
  inspectedAt: string;
  evidenceSha256: string;
};

/**
 * Returns null for incomplete report pagination, an unassessed/skipped
 * host, task/report mismatch, stale attestations, or concurrent Nessus
 * execution. A "Done" task alone is never accepted as coverage.
 *
 * The physical identity must match EXACTLY. An FQDN->IP correlation needs
 * independently reviewed binding evidence and is not guessed here.
 */
export function verifyGreenboneTerminalTarget(
  candidate: ExternalDispatchCandidate,
  expectedTaskId: string,
  nessus: NessusRunProof,
  untrusted: unknown,
  clockMs = Date.now(),
): GreenboneTerminalProof | null {
  const payload=obj(untrusted);
  const host=Array.isArray(payload?.hosts) && payload.hosts.length===1
    ? obj(payload.hosts[0]):null;
  const target=canonical(candidate?.target);
  const sourceTarget=Array.isArray(nessus?.coveredTargets) &&
    nessus.coveredTargets.length===1 ? canonical(nessus.coveredTargets[0]) : null;
  const attestedTarget=canonical(payload?.target);
  const assessedTarget=canonical(host?.identity);
  const occurrence=positiveTime(candidate?.scheduledOccurrenceAt);
  const sourceStarted=positiveTime(nessus?.startedAt);
  const sourceEnd=positiveTime(nessus?.completedAt);
  const greenboneStart=positiveTime(payload?.startedAt);
  const greenboneEnd=positiveTime(payload?.completedAt);
  const inspected=positiveTime(payload?.generatedAt);
  if (!Number.isFinite(clockMs) ||
      !candidate || typeof candidate.companyId!=="string" || !candidate.companyId.trim() ||
      !target || !sourceTarget || target!==sourceTarget ||
      target!==attestedTarget || target!==assessedTarget ||
      !Number.isSafeInteger(candidate.nessusScanId) || candidate.nessusScanId<1 ||
      !JOB_ID.test(expectedTaskId) || !payload ||
      payload.source!=="gvmd" || payload.inventoryComplete!==true ||
      payload.taskStatus!=="Done" || payload.reportStatus!=="Done" ||
      payload.reportComplete!==true || payload.allPagesComplete!==true ||
      payload.knownTargetCount!==1 || payload.reportedHostCount!==1 ||
      payload.taskId!==expectedTaskId || typeof payload.reportId!=="string" ||
      !UUID.test(payload.reportId) ||
      !host || host.status!=="completed" || host.assessed!==true ||
      typeof host.evidenceId!=="string" || !UUID.test(host.evidenceId) ||
      payload.skippedHostCount!==0 || payload.failedHostCount!==0 ||
      !Number.isSafeInteger(payload.reportResultCount) ||
      (payload.reportResultCount as number)<0 ||
      nessus.scanId!==candidate.nessusScanId ||
      nessus.status!=="completed" || typeof nessus.reportId!=="string" ||
      !UUID.test(nessus.reportId) ||
      occurrence===null || sourceStarted===null || sourceEnd===null ||
      greenboneStart===null || greenboneEnd===null || inspected===null ||
      sourceStarted<occurrence || sourceEnd<sourceStarted ||
      greenboneStart<occurrence+3_600_000 || greenboneStart<sourceEnd ||
      greenboneEnd<greenboneStart || greenboneEnd>inspected ||
      inspected>clockMs || clockMs-inspected>30_000)
    return null;

  // This digest fingerprints the *validated fields*, not a full GMP report.
  // It is a reconciliation handle, not a digital signature or proof that the
  // upstream endpoint is honest. The adapter remains a separate live gate.
  const values=[candidate.companyId,target,candidate.nessusScanId,
    new Date(occurrence).toISOString(),nessus.reportId,
    expectedTaskId,payload.reportId,host.evidenceId,
    new Date(greenboneStart).toISOString(),
    new Date(greenboneEnd).toISOString(),payload.reportResultCount];
  const evidenceSha256=createHash("sha256").update(JSON.stringify(values)).digest("hex");
  return {
    taskId:expectedTaskId,reportId:payload.reportId as string,target,
    nessusScanId:candidate.nessusScanId,nessusRunId:nessus.reportId,
    greenboneStartedAt:new Date(greenboneStart).toISOString(),
    greenboneCompletedAt:new Date(greenboneEnd).toISOString(),
    inspectedAt:new Date(inspected).toISOString(),evidenceSha256,
  };
}
