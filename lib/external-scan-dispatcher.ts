import type { Pool } from "pg";
import {
  evaluateExternalScanAdmission, externalScanDedupKey,
  type ExternalDispatchCandidate, type ExternalAdmissionInput,
} from "./external-scan-admission";
import { reserveExternalScanClaim, inspectExternalScanSlot } from "./db/external-scan-claims.mjs";
import { recordExternalScanRemoteTask, flagExternalScanReconciliation } from "./db/external-scan-reconciliation.mjs";

type Proofs = Pick<ExternalAdmissionInput, "scope" | "window" | "sourceRun" | "capacity">;

type TrustedDispatcherDeps = {
  db: Pick<Pool, "connect" | "query">;
  // These MUST read trusted live sources: approved routes, window, actual
  // Nessus run and Greenbone capacity. Never use request JSON as evidence.
  readProofs: (candidate: ExternalDispatchCandidate) => Promise<Proofs>;
  createTask: (candidate: ExternalDispatchCandidate, name: string,
    verify: () => Promise<void>) => Promise<string>;
  startTask: (candidate: ExternalDispatchCandidate, taskId: string,
    verify: () => Promise<void>) => Promise<void>;
};
type DispatchResult =
  | { state: "disabled" | "hold" | "busy" | "duplicate"; reason: string }
  | { state: "started"; taskId: string; claimKey: string }
  | { state: "reconciliation-required"; claimKey: string; taskId: string | null; stage: string };

function switchedOn(env: NodeJS.ProcessEnv): boolean {
  return env.VULN_EXTERNAL_SCAN_DISPATCH_ENABLED === "true" &&
    env.GMI_SCAN_ADMISSION_ENABLED === "true" &&
    env.VULNERS_BRIDGE_SCHEDULER_ENABLED !== "true";
}
function pin(proofs: Proofs): string {
  // Capacity is purposely excluded; it must be refreshed before every phase.
  return JSON.stringify([proofs.scope, proofs.window, proofs.sourceRun]);
}
async function latestEvidence(
  candidate: ExternalDispatchCandidate, deps: TrustedDispatcherDeps, env: NodeJS.ProcessEnv,
  expectedPin?: string,
): Promise<Proofs> {
  if (!switchedOn(env)) throw new Error("External dispatch controls changed.");
  const proofs = await deps.readProofs(candidate);
  if (expectedPin !== undefined && pin(proofs) !== expectedPin)
    throw new Error("Approved routing, maintenance window or Nessus run evidence changed.");
  const check = evaluateExternalScanAdmission({
    now: new Date().toISOString(), candidate, dispatchEnabled: true,
    scannerAdmissionEnabled: true,
    ...proofs,
    // This is *not* the global lock! Once reserved, the caller verifies
    // its own exact claim below and the DB singleton excludes all peers.
    claimExists: false,
  });
  if (check.state !== "eligible-for-atomic-claim")
    throw new Error(check.reason);
  return proofs;
}

/**
 * Controlled single-job launch. NOT wired to HTTP or any recurring timer.
 *
 * Caller must supply trusted proof loaders and split Greenbone create/start
 * adapters. The function requires both explicit flags and a globally empty
 * slot, pins approval, reserves durably, rechecks proofs before EACH remote
 * action, and saves the remote task ID BEFORE the start request.
 *
 * Every uncertain operation keeps the DB singleton occupied indefinitely
 * until an operator confirms actual remote state. This intentionally does
 * not poll results, auto-retry, release the slot or declare a scan completed.
 */
export async function dispatchOneAuthorizedExternalTarget(
  candidate: ExternalDispatchCandidate, deps: TrustedDispatcherDeps,
  env: NodeJS.ProcessEnv = process.env,
): Promise<DispatchResult> {
  if (!switchedOn(env))
    return { state: "disabled", reason: "External dispatch or scanner admission is disabled." };
  const claimKey = externalScanDedupKey(candidate);
  if (!claimKey) return { state: "hold", reason: "Invalid customer target or occurrence identity." };
  let first: Proofs;
  try {
    first = await latestEvidence(candidate, deps, env);
  } catch (error) {
    return { state: "hold", reason: error instanceof Error ? error.message : "Live proof unavailable." };
  }
  const reserved = await reserveExternalScanClaim(deps.db, {
    dedupKey: claimKey, companyId: candidate.companyId,
    target: candidate.target.toLowerCase().replace(/\.$/, ""),
    nessusScanId: candidate.nessusScanId,
    occurrenceAt: candidate.scheduledOccurrenceAt,
  });
  if (reserved.state !== "reserved")
    return { state: reserved.state, reason: "External scan slot already occupied or occurrence previously claimed." };
  const pinned = pin(first);
  let stage = "post-reservation-check", taskId: string | null = null;
  const verify = async () => {
    const slot = await inspectExternalScanSlot(deps.db);
    if (slot.claim_key !== claimKey)
      throw new Error("Lost the global scan reservation.");
    await latestEvidence(candidate, deps, env, pinned);
  };
  try {
    await verify();
    stage = "create";
    // The unique claim prefix avoids a Greenbone target-name collision.
    taskId = await deps.createTask(candidate, `[reserved:${claimKey.slice(0, 16)}] ${candidate.target}`, verify);
    stage = "persist-task-id";
    await recordExternalScanRemoteTask(deps.db, claimKey, taskId);
    stage = "pre-start-check";
    await verify();
    stage = "start";
    await deps.startTask(candidate, taskId, verify);
    // No completion claims or slot release here. An independent report
    // consumer must later verify the remote task and full report.
    return { state: "started", taskId, claimKey };
  } catch {
    // Even when we know no create was sent, retain the claim; manual
    // reconciliation is safer than silently releasing a disputed slot.
    await flagExternalScanReconciliation(
      deps.db, claimKey, `Controlled dispatch uncertain at ${stage}; inspect Greenbone before another attempt.`,
    );
    return { state: "reconciliation-required", claimKey, taskId, stage };
  }
}
