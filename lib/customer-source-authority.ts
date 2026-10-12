import { createHash } from "node:crypto";
import type { CustomerSourceRead } from "./customer-source-read-model";

export type SourceDomain = "endpoint-findings" | "web-findings" | "exposures" | "inventory" | "enrichment" | "saved-queries";
export type SourceAuthority = "unassigned" | "findings-primary" | "inventory" | "enrichment" | "query-only" | "mirror";
/** Trusted collector/reviewer evidence for an offline decision preview. Not an active binding or an HTTP input. */
export type AuthorityEvidence = {
  id: string; companyId: string; provider: string; domain: SourceDomain; authority: SourceAuthority;
  originKey: string; mirrorOf: string | null; configured: boolean; sourcePresent: boolean;
  sourceFingerprint: string; reviewedSelectionHash: string | null; scopeVerified: boolean;
  reader: "defender-saved-v1" | "spotlight-summary-v1" | null;
};
const domains = ["endpoint-findings","web-findings","exposures","inventory","enrichment","saved-queries"];
const roles = ["unassigned","findings-primary","inventory","enrichment","query-only","mirror"];
const short = (value: unknown) => typeof value === "string" && value.length > 0 && value.length <= 256 && !/[\x00-\x1f\x7f]/.test(value);
const digest = (value: unknown) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

// Scope, configuration evidence and proposed role/mirror changes all invalidate review.
// Import progress/freshness do not silently rewrite the approved source selection.
export function sourceSelectionHash(binding: AuthorityEvidence) {
  return createHash("sha256").update(JSON.stringify([binding.id,binding.companyId,binding.provider,binding.domain,
    binding.authority,binding.originKey,binding.mirrorOf,binding.sourceFingerprint,binding.reader])).digest("hex");
}
function validate(binding: AuthorityEvidence) {
  if (![binding.id,binding.companyId,binding.provider,binding.originKey].every(short) || !domains.includes(binding.domain) ||
    !roles.includes(binding.authority) || !digest(binding.sourceFingerprint) ||
    (binding.reviewedSelectionHash !== null && !digest(binding.reviewedSelectionHash)) ||
    (binding.mirrorOf !== null && !short(binding.mirrorOf)) ||
    ![binding.configured,binding.sourcePresent,binding.scopeVerified].every(v => typeof v === "boolean") ||
    ![null,"defender-saved-v1","spotlight-summary-v1"].includes(binding.reader)) throw new Error("Invalid source authority evidence.");
}

/** No database, API, activation or routing side effects. Never returns a summed platform count. */
export function planCustomerSourceAuthority(companyId: string, evidence: readonly AuthorityEvidence[], results: Record<string, CustomerSourceRead> = {}) {
  if (typeof companyId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(companyId) || !Array.isArray(evidence) || evidence.length > 10000)
    throw new Error("An explicit customer and bounded evidence list are required.");
  const bindings = evidence.filter(b => b?.companyId === companyId).sort((a,b) => a.id.localeCompare(b.id));
  bindings.forEach(validate);
  if (new Set(bindings.map(b => b.id)).size !== bindings.length) throw new Error("Duplicate source binding identity.");
  const issues: {bindingId: string; code: string}[] = [];
  const issue = (b: AuthorityEvidence, code: string) => issues.push({bindingId:b.id,code});
  const endpoint = bindings.filter(b => b.domain === "endpoint-findings" && b.authority !== "query-only");
  const primaries = endpoint.filter(b => b.authority === "findings-primary");
  for (const b of endpoint) {
    if (!b.configured || !b.sourcePresent) issue(b,"source-not-configured-or-present");
    if (!b.scopeVerified) issue(b,"customer-source-scope-unverified");
    if (b.reviewedSelectionHash !== sourceSelectionHash(b)) issue(b,"selection-needs-review");
    if (!["findings-primary","mirror"].includes(b.authority)) issue(b,"endpoint-authority-unassigned-or-invalid");
    if (b.authority === "findings-primary" && b.mirrorOf !== null) issue(b,"primary-cannot-reference-mirror");
    if (b.authority === "mirror") {
      const target = primaries.find(p => p.id === b.mirrorOf);
      if (!target || target.originKey !== b.originKey) issue(b,"mirror-origin-or-target-unverified");
    }
  }
  for (const b of primaries) {
    if (primaries.some(other => other.id !== b.id && other.originKey === b.originKey)) issue(b,"duplicate-primary-origin");
    const supported = (b.provider === "defender" && b.reader === "defender-saved-v1") ||
      (b.provider === "crowdstrike" && b.reader === "spotlight-summary-v1");
    if (!supported) issue(b,"saved-reader-unavailable");
  }
  const observations = primaries.map(b => {
    const value = Object.hasOwn(results,b.id) ? results[b.id] : undefined;
    if (value && (value.companyId !== companyId || value.source !== b.provider)) throw new Error("Saved evidence belongs to a different customer or provider.");
    if (value?.state === "available" && value.generation.revisionMatches === false) issue(b,"completed-evidence-configuration-mismatch");
    return {bindingId:b.id,provider:b.provider,state:value?.state ?? "not-loaded",
      generationId:value?.state === "available" ? value.generation.id : null,
      freshness:value?.state === "available" ? value.generation.freshness : null,
      revisionMatches:value?.state === "available" ? value.generation.revisionMatches ?? null : null,
      summaryPending:value?.projection?.state === "pending",
      latestAttempt:value?.latestAttempt?.status ?? null};
  });
  const state = issues.length ? "needs-review" : !primaries.length ? "no-findings-source" : primaries.length > 1 ? "requires-record-correlation" : "ready-for-comparison";
  return {version:1 as const,mode:"preview-only" as const,scope:"endpoint-source-selection" as const,companyId,state,
    proposedSources:primaries.map(b => b.id), excludedMirrors:endpoint.filter(b => b.authority === "mirror").map(b => b.id),
    otherDomains:bindings.filter(b => !endpoint.includes(b)).map(b => ({bindingId:b.id,domain:b.domain,authority:b.authority})),
    issues,observations,combinedPlatformFindings:null,canActivate:false as const};
}
