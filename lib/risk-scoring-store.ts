import { randomUUID } from "node:crypto";
import { applicationDatabase } from "./persist";
import { DashboardError } from "./elastic-dashboard";
import { DEFAULT_RISK_WEIGHTS, DEFAULT_SWATH_THRESHOLDS, type RiskWeights, type SwathThresholds } from "./risk-scoring";

// finding_risk is keyed by (tenant_key, cve, host_key) -- a STABLE identity
// independent of any one Spotlight import generation. spotlight_import_records
// (lib/spotlight-record-store.ts) is replaced wholesale on every completed
// import run, so risk scores, Swath overrides, and verification status can't
// live there or they'd be lost the next time an import completes.
//
// Deliberately applicationDatabase(), NOT dashboardDatabase(): this module
// runs raw SQL joins directly against spotlight_import_records/
// spotlight_import_current, which lib/spotlight-record-store.ts writes
// exclusively through applicationDatabase(). dashboardDatabase() can point
// at a separate ELASTIC_VULN_DATABASE_URL pool when one is configured --
// using it here would mean this module's tables and the Spotlight tables
// could live in two different physical databases, so every join would
// silently return zero rows (this is the exact bug a live production run
// hit: refreshAllTenantsRisk found 0 tenants despite Atlas clearly having
// Spotlight data, because finding_risk et al had been created in the wrong
// database). See docs/superpowers/specs/2026-09-29-postgres-source-of-truth
// -design.md for the broader, still-unresolved two-database split this
// session already knew about.
let ready: Promise<void> | undefined;
export async function riskScoringDatabase() {
  const db = applicationDatabase();
  if (!db) throw new DashboardError("Database storage is not configured.", 503);
  ready ??= db.query(`
    CREATE TABLE IF NOT EXISTS finding_risk (
      id UUID PRIMARY KEY, tenant_key TEXT NOT NULL, company_id TEXT NOT NULL,
      cve TEXT NOT NULL, host_key TEXT NOT NULL, hostname TEXT, severity TEXT,
      risk_score INT NOT NULL, technical_score INT NOT NULL, exploit_likelihood_score INT NOT NULL,
      threat_activity_score INT NOT NULL, asset_context_score INT NOT NULL, additional_context_score INT NOT NULL,
      reasons JSONB NOT NULL DEFAULT '[]',
      calculated_swath INT NOT NULL, effective_swath INT NOT NULL,
      swath_override_by TEXT, swath_override_at TIMESTAMPTZ, swath_override_reason TEXT,
      epss_probability REAL, epss_percentile REAL, cisa_kev BOOLEAN NOT NULL DEFAULT false,
      known_exploit BOOLEAN NOT NULL DEFAULT false, active_exploitation BOOLEAN NOT NULL DEFAULT false,
      ransomware_association BOOLEAN NOT NULL DEFAULT false, internet_exposed BOOLEAN NOT NULL DEFAULT false,
      asset_criticality TEXT NOT NULL DEFAULT 'Normal',
      verification_status TEXT NOT NULL DEFAULT 'detected',
      verified_at TIMESTAMPTZ, risk_removed INT,
      risk_calculated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      first_seen TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(tenant_key, cve, host_key)
    );
    CREATE INDEX IF NOT EXISTS finding_risk_company_idx ON finding_risk(company_id);
    CREATE INDEX IF NOT EXISTS finding_risk_score_idx ON finding_risk(risk_score DESC);
    CREATE INDEX IF NOT EXISTS finding_risk_swath_idx ON finding_risk(effective_swath);
    CREATE TABLE IF NOT EXISTS cve_enrichment (
      cve TEXT PRIMARY KEY, cvss_score REAL, cvss_severity TEXT,
      epss_probability REAL, epss_percentile REAL,
      cisa_kev BOOLEAN NOT NULL DEFAULT false, kev_date_added DATE, kev_ransomware BOOLEAN NOT NULL DEFAULT false,
      active_exploitation BOOLEAN NOT NULL DEFAULT false, active_exploitation_source TEXT, active_exploitation_detail TEXT,
      published_date DATE, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS risk_history (
      id UUID PRIMARY KEY, finding_risk_id UUID NOT NULL, changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      field TEXT NOT NULL, old_value TEXT, new_value TEXT, reason TEXT, actor TEXT
    );
    CREATE INDEX IF NOT EXISTS risk_history_finding_idx ON risk_history(finding_risk_id, changed_at DESC);
    CREATE TABLE IF NOT EXISTS risk_snapshots (
      id UUID PRIMARY KEY, taken_at TIMESTAMPTZ NOT NULL DEFAULT now(), scope TEXT NOT NULL,
      total_open_risk BIGINT NOT NULL, swath1_count INT NOT NULL, swath2_count INT NOT NULL,
      swath3_count INT NOT NULL, swath4_count INT NOT NULL, kev_open_count INT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS risk_snapshots_scope_idx ON risk_snapshots(scope, taken_at DESC);
    CREATE TABLE IF NOT EXISTS risk_config (
      id INT PRIMARY KEY CHECK (id=1), weights JSONB NOT NULL, swath_thresholds JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_by TEXT
    );
  `).then(() => {});
  await ready;
  return db;
}

export type FindingRiskRow = {
  id: string; tenantKey: string; companyId: string; cve: string; hostKey: string; hostname: string; severity: string;
  riskScore: number; technicalScore: number; exploitLikelihoodScore: number; threatActivityScore: number;
  assetContextScore: number; additionalContextScore: number; reasons: string[];
  calculatedSwath: number; effectiveSwath: number; swathOverrideBy: string | null; swathOverrideAt: string | null; swathOverrideReason: string | null;
  epssProbability: number | null; epssPercentile: number | null; cisaKev: boolean; knownExploit: boolean; activeExploitation: boolean;
  ransomwareAssociation: boolean; internetExposed: boolean; assetCriticality: string;
  verificationStatus: string; verifiedAt: string | null; riskRemoved: number | null;
  riskCalculatedAt: string; firstSeen: string; lastSeen: string;
};

function fromRow(row: any): FindingRiskRow {
  return {
    id: row.id, tenantKey: row.tenant_key, companyId: row.company_id, cve: row.cve, hostKey: row.host_key,
    hostname: row.hostname ?? "", severity: row.severity ?? "",
    riskScore: row.risk_score, technicalScore: row.technical_score, exploitLikelihoodScore: row.exploit_likelihood_score,
    threatActivityScore: row.threat_activity_score, assetContextScore: row.asset_context_score, additionalContextScore: row.additional_context_score,
    reasons: row.reasons ?? [],
    calculatedSwath: row.calculated_swath, effectiveSwath: row.effective_swath,
    swathOverrideBy: row.swath_override_by, swathOverrideAt: row.swath_override_at ? new Date(row.swath_override_at).toISOString() : null,
    swathOverrideReason: row.swath_override_reason,
    epssProbability: row.epss_probability, epssPercentile: row.epss_percentile, cisaKev: row.cisa_kev,
    knownExploit: row.known_exploit, activeExploitation: row.active_exploitation, ransomwareAssociation: row.ransomware_association,
    internetExposed: row.internet_exposed, assetCriticality: row.asset_criticality,
    verificationStatus: row.verification_status, verifiedAt: row.verified_at ? new Date(row.verified_at).toISOString() : null,
    riskRemoved: row.risk_removed,
    riskCalculatedAt: new Date(row.risk_calculated_at).toISOString(),
    firstSeen: new Date(row.first_seen).toISOString(), lastSeen: new Date(row.last_seen).toISOString(),
  };
}

export type UpsertFindingRiskInput = {
  tenantKey: string; companyId: string; cve: string; hostKey: string; hostname: string; severity: string;
  riskScore: number; technicalScore: number; exploitLikelihoodScore: number; threatActivityScore: number;
  assetContextScore: number; additionalContextScore: number; reasons: string[];
  calculatedSwath: number; effectiveSwath: number;
  epssProbability: number | null; epssPercentile: number | null; cisaKev: boolean; knownExploit: boolean;
  activeExploitation: boolean; ransomwareAssociation: boolean; internetExposed: boolean; assetCriticality: string;
  verificationStatus?: string;
};

// Upserts one finding's computed risk, preserving any analyst Swath override
// (a fresh recalculation must never silently clobber a human decision) and
// recording risk_history when the score or effective Swath materially moves,
// so "why did this become higher priority" stays answerable later.
export async function upsertFindingRisk(db: Awaited<ReturnType<typeof riskScoringDatabase>>, input: UpsertFindingRiskInput): Promise<{ id: string; scoreChanged: boolean }> {
  const existing = (await db.query(
    "SELECT id, risk_score, effective_swath, swath_override_by, verification_status FROM finding_risk WHERE tenant_key=$1 AND cve=$2 AND host_key=$3",
    [input.tenantKey, input.cve, input.hostKey],
  )).rows[0] as { id: string; risk_score: number; effective_swath: number; swath_override_by: string | null; verification_status: string } | undefined;

  const effectiveSwath = existing?.swath_override_by ? existing.effective_swath : input.effectiveSwath;
  // A verified-remediated finding stays verified through a recalculation --
  // only setVerificationStatus/a fresh ticket-coverage change should move it
  // off that state, never a routine rescore overwriting it back to "detected".
  const verificationStatus = existing?.verification_status === "verified_remediated" ? "verified_remediated" : (input.verificationStatus ?? existing?.verification_status ?? "detected");
  const verifiedAtClause = verificationStatus === "verified_remediated" && existing?.verification_status !== "verified_remediated" ? "now()" : existing ? "finding_risk.verified_at" : "NULL";
  const id = existing?.id ?? randomUUID();
  await db.query(`
    INSERT INTO finding_risk (id, tenant_key, company_id, cve, host_key, hostname, severity,
      risk_score, technical_score, exploit_likelihood_score, threat_activity_score, asset_context_score, additional_context_score, reasons,
      calculated_swath, effective_swath, epss_probability, epss_percentile, cisa_kev, known_exploit, active_exploitation,
      ransomware_association, internet_exposed, asset_criticality, verification_status, risk_calculated_at, last_seen)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,now(),now())
    ON CONFLICT (tenant_key, cve, host_key) DO UPDATE SET
      company_id=$3, hostname=$6, severity=$7, risk_score=$8, technical_score=$9, exploit_likelihood_score=$10,
      threat_activity_score=$11, asset_context_score=$12, additional_context_score=$13, reasons=$14,
      calculated_swath=$15, effective_swath=CASE WHEN finding_risk.swath_override_by IS NULL THEN $16 ELSE finding_risk.effective_swath END,
      epss_probability=$17, epss_percentile=$18, cisa_kev=$19, known_exploit=$20, active_exploitation=$21,
      ransomware_association=$22, internet_exposed=$23, asset_criticality=$24, verification_status=$25,
      verified_at=${verifiedAtClause}, risk_calculated_at=now(), last_seen=now()
  `, [id, input.tenantKey, input.companyId, input.cve, input.hostKey, input.hostname, input.severity,
    input.riskScore, input.technicalScore, input.exploitLikelihoodScore, input.threatActivityScore, input.assetContextScore, input.additionalContextScore, JSON.stringify(input.reasons),
    input.calculatedSwath, input.effectiveSwath, input.epssProbability, input.epssPercentile, input.cisaKev, input.knownExploit, input.activeExploitation,
    input.ransomwareAssociation, input.internetExposed, input.assetCriticality, verificationStatus]);

  const scoreChanged = !existing || existing.risk_score !== input.riskScore;
  if (existing && existing.risk_score !== input.riskScore) {
    await recordRiskHistory(db, id, "risk_score", String(existing.risk_score), String(input.riskScore), input.reasons.slice(0, 3).join("; ") || null, "risk-engine");
  }
  if (existing && existing.effective_swath !== effectiveSwath && !existing.swath_override_by) {
    await recordRiskHistory(db, id, "effective_swath", String(existing.effective_swath), String(effectiveSwath), "Recalculated", "risk-engine");
  }
  if (existing && existing.verification_status !== verificationStatus) {
    await recordRiskHistory(db, id, "verification_status", existing.verification_status, verificationStatus, null, "risk-engine");
  }
  return { id, scoreChanged };
}

// Batched sibling of upsertFindingRisk, for a bulk recompute pass (hundreds
// of thousands to millions of findings). upsertFindingRisk's one
// SELECT-then-INSERT round trip per finding is fine at ordinary scale but
// becomes hours of sequential network latency once a tenant has millions of
// findings (the first real-world run at that scale is what surfaced this).
// Same logic as upsertFindingRisk -- override preservation, verification
// status stickiness, risk_history on material change -- just resolved
// against one batch existing-lookup instead of one per finding, and written
// with one multi-row upsert instead of one per finding. upsertFindingRisk
// itself is untouched for callers that still want single-finding semantics.
export async function upsertFindingRiskBatch(
  db: Awaited<ReturnType<typeof riskScoringDatabase>>,
  tenantKey: string,
  inputs: UpsertFindingRiskInput[],
): Promise<{ scored: number }> {
  if (!inputs.length) return { scored: 0 };

  const keys = inputs.map((i) => ({ cve: i.cve, host_key: i.hostKey }));
  const existingRows = (await db.query(`
    SELECT fr.id, fr.cve, fr.host_key, fr.risk_score, fr.effective_swath, fr.swath_override_by, fr.verification_status, fr.verified_at
    FROM finding_risk fr
    JOIN jsonb_to_recordset($2::jsonb) AS k(cve TEXT, host_key TEXT) ON fr.cve = k.cve AND fr.host_key = k.host_key
    WHERE fr.tenant_key = $1
  `, [tenantKey, JSON.stringify(keys)])).rows as {
    id: string; cve: string; host_key: string; risk_score: number; effective_swath: number;
    swath_override_by: string | null; verification_status: string; verified_at: string | null;
  }[];
  const existingByKey = new Map(existingRows.map((r) => [`${r.cve}\u0000${r.host_key}`, r]));

  const rows: Record<string, unknown>[] = [];
  const historyRows: { id: string; finding_risk_id: string; field: string; old_value: string | null; new_value: string | null; reason: string | null }[] = [];

  for (const input of inputs) {
    const existing = existingByKey.get(`${input.cve}\u0000${input.hostKey}`);
    // Same stickiness rules as upsertFindingRisk: a human Swath override and
    // a verified-remediated status both survive a routine recalculation.
    const effectiveSwathForHistory = existing?.swath_override_by ? existing.effective_swath : input.effectiveSwath;
    const verificationStatus = existing?.verification_status === "verified_remediated"
      ? "verified_remediated" : (input.verificationStatus ?? existing?.verification_status ?? "detected");
    const newlyVerified = verificationStatus === "verified_remediated" && existing?.verification_status !== "verified_remediated";
    const verifiedAt = newlyVerified ? new Date().toISOString() : (existing ? existing.verified_at : null);
    const id = existing?.id ?? randomUUID();
    rows.push({
      id, tenant_key: input.tenantKey, company_id: input.companyId, cve: input.cve, host_key: input.hostKey,
      hostname: input.hostname, severity: input.severity,
      risk_score: input.riskScore, technical_score: input.technicalScore, exploit_likelihood_score: input.exploitLikelihoodScore,
      threat_activity_score: input.threatActivityScore, asset_context_score: input.assetContextScore, additional_context_score: input.additionalContextScore,
      reasons: input.reasons,
      calculated_swath: input.calculatedSwath, effective_swath: input.effectiveSwath,
      epss_probability: input.epssProbability, epss_percentile: input.epssPercentile, cisa_kev: input.cisaKev,
      known_exploit: input.knownExploit, active_exploitation: input.activeExploitation,
      ransomware_association: input.ransomwareAssociation, internet_exposed: input.internetExposed,
      asset_criticality: input.assetCriticality, verification_status: verificationStatus, verified_at: verifiedAt,
    });
    if (existing && existing.risk_score !== input.riskScore)
      historyRows.push({ id: randomUUID(), finding_risk_id: id, field: "risk_score", old_value: String(existing.risk_score), new_value: String(input.riskScore), reason: input.reasons.slice(0, 3).join("; ") || null });
    if (existing && existing.effective_swath !== effectiveSwathForHistory && !existing.swath_override_by)
      historyRows.push({ id: randomUUID(), finding_risk_id: id, field: "effective_swath", old_value: String(existing.effective_swath), new_value: String(effectiveSwathForHistory), reason: "Recalculated" });
    if (existing && existing.verification_status !== verificationStatus)
      historyRows.push({ id: randomUUID(), finding_risk_id: id, field: "verification_status", old_value: existing.verification_status, new_value: verificationStatus, reason: null });
  }

  await db.query(`
    INSERT INTO finding_risk (id, tenant_key, company_id, cve, host_key, hostname, severity,
      risk_score, technical_score, exploit_likelihood_score, threat_activity_score, asset_context_score, additional_context_score, reasons,
      calculated_swath, effective_swath, epss_probability, epss_percentile, cisa_kev, known_exploit, active_exploitation,
      ransomware_association, internet_exposed, asset_criticality, verification_status, verified_at, risk_calculated_at, last_seen)
    SELECT r.id, r.tenant_key, r.company_id, r.cve, r.host_key, r.hostname, r.severity,
      r.risk_score, r.technical_score, r.exploit_likelihood_score, r.threat_activity_score, r.asset_context_score, r.additional_context_score, r.reasons,
      r.calculated_swath, r.effective_swath, r.epss_probability, r.epss_percentile, r.cisa_kev, r.known_exploit, r.active_exploitation,
      r.ransomware_association, r.internet_exposed, r.asset_criticality, r.verification_status, r.verified_at, now(), now()
    FROM jsonb_to_recordset($1::jsonb) AS r(
      id UUID, tenant_key TEXT, company_id TEXT, cve TEXT, host_key TEXT, hostname TEXT, severity TEXT,
      risk_score INT, technical_score INT, exploit_likelihood_score INT, threat_activity_score INT, asset_context_score INT, additional_context_score INT, reasons JSONB,
      calculated_swath INT, effective_swath INT, epss_probability REAL, epss_percentile REAL, cisa_kev BOOLEAN, known_exploit BOOLEAN, active_exploitation BOOLEAN,
      ransomware_association BOOLEAN, internet_exposed BOOLEAN, asset_criticality TEXT, verification_status TEXT, verified_at TIMESTAMPTZ)
    ON CONFLICT (tenant_key, cve, host_key) DO UPDATE SET
      company_id=EXCLUDED.company_id, hostname=EXCLUDED.hostname, severity=EXCLUDED.severity, risk_score=EXCLUDED.risk_score,
      technical_score=EXCLUDED.technical_score, exploit_likelihood_score=EXCLUDED.exploit_likelihood_score,
      threat_activity_score=EXCLUDED.threat_activity_score, asset_context_score=EXCLUDED.asset_context_score, additional_context_score=EXCLUDED.additional_context_score,
      reasons=EXCLUDED.reasons, calculated_swath=EXCLUDED.calculated_swath,
      effective_swath=CASE WHEN finding_risk.swath_override_by IS NULL THEN EXCLUDED.effective_swath ELSE finding_risk.effective_swath END,
      epss_probability=EXCLUDED.epss_probability, epss_percentile=EXCLUDED.epss_percentile, cisa_kev=EXCLUDED.cisa_kev,
      known_exploit=EXCLUDED.known_exploit, active_exploitation=EXCLUDED.active_exploitation, ransomware_association=EXCLUDED.ransomware_association,
      internet_exposed=EXCLUDED.internet_exposed, asset_criticality=EXCLUDED.asset_criticality, verification_status=EXCLUDED.verification_status,
      verified_at=EXCLUDED.verified_at, risk_calculated_at=now(), last_seen=now()
  `, [JSON.stringify(rows)]);

  if (historyRows.length) {
    await db.query(`
      INSERT INTO risk_history (id, finding_risk_id, changed_at, field, old_value, new_value, reason, actor)
      SELECT h.id, h.finding_risk_id, now(), h.field, h.old_value, h.new_value, h.reason, 'risk-engine'
      FROM jsonb_to_recordset($1::jsonb) AS h(id UUID, finding_risk_id UUID, field TEXT, old_value TEXT, new_value TEXT, reason TEXT)
    `, [JSON.stringify(historyRows)]);
  }

  return { scored: inputs.length };
}

export async function recordRiskHistory(db: Awaited<ReturnType<typeof riskScoringDatabase>>, findingRiskId: string, field: string, oldValue: string | null, newValue: string | null, reason: string | null, actor: string): Promise<void> {
  await db.query("INSERT INTO risk_history (id, finding_risk_id, field, old_value, new_value, reason, actor) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    [randomUUID(), findingRiskId, field, oldValue, newValue, reason, actor]);
}

export type TopRiskFilter = { companyId?: string; tenantKey?: string; swath?: number; kevOnly?: boolean; internetExposedOnly?: boolean; minScore?: number; limit?: number; offset?: number };

export async function listTopRisk(db: Awaited<ReturnType<typeof riskScoringDatabase>>, filter: TopRiskFilter = {}): Promise<{ rows: FindingRiskRow[]; total: number }> {
  const clauses: string[] = []; const params: unknown[] = [];
  const push = (clause: string, value: unknown) => { params.push(value); clauses.push(clause.replace("$$", `$${params.length}`)); };
  if (filter.companyId) push("company_id=$$", filter.companyId);
  if (filter.tenantKey) push("tenant_key=$$", filter.tenantKey);
  if (filter.swath) push("effective_swath=$$", filter.swath);
  if (filter.kevOnly) clauses.push("cisa_kev=true");
  if (filter.internetExposedOnly) clauses.push("internet_exposed=true");
  if (filter.minScore != null) push("risk_score>=$$", filter.minScore);
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const limit = Math.min(filter.limit ?? 200, 1000), offset = filter.offset ?? 0;
  const [rows, count] = await Promise.all([
    db.query(`SELECT * FROM finding_risk ${where} ORDER BY risk_score DESC LIMIT ${limit} OFFSET ${offset}`, params),
    db.query(`SELECT count(*)::int AS n FROM finding_risk ${where}`, params),
  ]);
  return { rows: rows.rows.map(fromRow), total: count.rows[0].n };
}

export type RiskSummary = {
  totalOpenRisk: number; criticalRiskCount: number; swath1Open: number; swath2Open: number;
  kevOpen: number; internetFacingCriticalRisk: number; verifiedRemediations: number; awaitingVerification: number;
};

export async function getRiskSummary(db: Awaited<ReturnType<typeof riskScoringDatabase>>, companyId?: string): Promise<RiskSummary> {
  const where = companyId ? "WHERE company_id=$1" : "";
  const params = companyId ? [companyId] : [];
  const row = (await db.query(`
    SELECT
      coalesce(sum(risk_score) FILTER (WHERE verification_status NOT IN ('verified_remediated')), 0)::bigint AS total_open_risk,
      count(*) FILTER (WHERE risk_score >= 800 AND verification_status NOT IN ('verified_remediated'))::int AS critical_risk_count,
      count(*) FILTER (WHERE effective_swath=1 AND verification_status NOT IN ('verified_remediated'))::int AS swath1_open,
      count(*) FILTER (WHERE effective_swath=2 AND verification_status NOT IN ('verified_remediated'))::int AS swath2_open,
      count(*) FILTER (WHERE cisa_kev AND verification_status NOT IN ('verified_remediated'))::int AS kev_open,
      count(*) FILTER (WHERE internet_exposed AND risk_score >= 800 AND verification_status NOT IN ('verified_remediated'))::int AS internet_facing_critical_risk,
      count(*) FILTER (WHERE verification_status='verified_remediated')::int AS verified_remediations,
      count(*) FILTER (WHERE verification_status='pending_verification')::int AS awaiting_verification
    FROM finding_risk ${where}
  `, params)).rows[0];
  return {
    totalOpenRisk: Number(row.total_open_risk), criticalRiskCount: row.critical_risk_count,
    swath1Open: row.swath1_open, swath2Open: row.swath2_open, kevOpen: row.kev_open,
    internetFacingCriticalRisk: row.internet_facing_critical_risk,
    verifiedRemediations: row.verified_remediations, awaitingVerification: row.awaiting_verification,
  };
}

// An analyst override always wins over the next recalculation (see
// upsertFindingRisk's CASE above) until explicitly cleared.
export async function overrideSwath(db: Awaited<ReturnType<typeof riskScoringDatabase>>, findingRiskId: string, newSwath: number, actor: string, reason: string): Promise<void> {
  const existing = (await db.query("SELECT effective_swath FROM finding_risk WHERE id=$1", [findingRiskId])).rows[0] as { effective_swath: number } | undefined;
  if (!existing) throw new Error("Finding not found");
  await db.query("UPDATE finding_risk SET effective_swath=$2, swath_override_by=$3, swath_override_at=now(), swath_override_reason=$4 WHERE id=$1",
    [findingRiskId, newSwath, actor, reason]);
  await recordRiskHistory(db, findingRiskId, "effective_swath", String(existing.effective_swath), String(newSwath), reason, actor);
}

export async function clearSwathOverride(db: Awaited<ReturnType<typeof riskScoringDatabase>>, findingRiskId: string, actor: string): Promise<void> {
  await db.query("UPDATE finding_risk SET effective_swath=calculated_swath, swath_override_by=NULL, swath_override_at=NULL, swath_override_reason=NULL WHERE id=$1", [findingRiskId]);
  await recordRiskHistory(db, findingRiskId, "swath_override", "cleared", null, "Override cleared, reverted to calculated Swath", actor);
}

export async function setVerificationStatus(db: Awaited<ReturnType<typeof riskScoringDatabase>>, findingRiskId: string, status: string, actor: string): Promise<void> {
  const verifiedAt = status === "verified_remediated" ? "now()" : "NULL";
  await db.query(`UPDATE finding_risk SET verification_status=$2, verified_at=${verifiedAt} WHERE id=$1`, [findingRiskId, status]);
  await recordRiskHistory(db, findingRiskId, "verification_status", null, status, null, actor);
}

export type CveEnrichmentRow = {
  cve: string; cvssScore: number | null; cvssSeverity: string | null; epssProbability: number | null; epssPercentile: number | null;
  cisaKev: boolean; kevDateAdded: string | null; kevRansomware: boolean; publishedDate: string | null;
  activeExploitation: boolean; activeExploitationSource: string | null; activeExploitationDetail: string | null;
};

export async function getCveEnrichment(db: Awaited<ReturnType<typeof riskScoringDatabase>>, cves: string[]): Promise<Map<string, CveEnrichmentRow>> {
  if (!cves.length) return new Map();
  const rows = (await db.query("SELECT * FROM cve_enrichment WHERE cve = ANY($1::text[])", [cves])).rows;
  const out = new Map<string, CveEnrichmentRow>();
  for (const row of rows) out.set(row.cve, {
    cve: row.cve, cvssScore: row.cvss_score, cvssSeverity: row.cvss_severity,
    epssProbability: row.epss_probability, epssPercentile: row.epss_percentile,
    cisaKev: row.cisa_kev, kevDateAdded: row.kev_date_added, kevRansomware: row.kev_ransomware,
    publishedDate: row.published_date,
    activeExploitation: row.active_exploitation, activeExploitationSource: row.active_exploitation_source, activeExploitationDetail: row.active_exploitation_detail,
  });
  return out;
}

export async function upsertCveEnrichment(db: Awaited<ReturnType<typeof riskScoringDatabase>>, rows: (Partial<CveEnrichmentRow> & { cve: string })[]): Promise<void> {
  for (const row of rows) {
    await db.query(`
      INSERT INTO cve_enrichment (cve, cvss_score, cvss_severity, epss_probability, epss_percentile, cisa_kev, kev_date_added, kev_ransomware, published_date,
        active_exploitation, active_exploitation_source, active_exploitation_detail, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())
      ON CONFLICT (cve) DO UPDATE SET
        cvss_score=coalesce($2, cve_enrichment.cvss_score), cvss_severity=coalesce($3, cve_enrichment.cvss_severity),
        epss_probability=coalesce($4, cve_enrichment.epss_probability), epss_percentile=coalesce($5, cve_enrichment.epss_percentile),
        cisa_kev=$6 OR cve_enrichment.cisa_kev, kev_date_added=coalesce($7, cve_enrichment.kev_date_added),
        kev_ransomware=$8 OR cve_enrichment.kev_ransomware, published_date=coalesce($9, cve_enrichment.published_date),
        active_exploitation=$10 OR cve_enrichment.active_exploitation,
        active_exploitation_source=coalesce($11, cve_enrichment.active_exploitation_source),
        active_exploitation_detail=coalesce($12, cve_enrichment.active_exploitation_detail), updated_at=now()
    `, [row.cve, row.cvssScore ?? null, row.cvssSeverity ?? null, row.epssProbability ?? null, row.epssPercentile ?? null,
      row.cisaKev ?? false, row.kevDateAdded ?? null, row.kevRansomware ?? false, row.publishedDate ?? null,
      row.activeExploitation ?? false, row.activeExploitationSource ?? null, row.activeExploitationDetail ?? null]);
  }
}

export async function recordRiskSnapshot(db: Awaited<ReturnType<typeof riskScoringDatabase>>, scope: string): Promise<void> {
  const where = scope === "global" ? "" : "WHERE company_id=$1";
  const params = scope === "global" ? [] : [scope];
  const row = (await db.query(`
    SELECT coalesce(sum(risk_score) FILTER (WHERE verification_status NOT IN ('verified_remediated')), 0)::bigint AS total,
      count(*) FILTER (WHERE effective_swath=1 AND verification_status NOT IN ('verified_remediated'))::int AS s1,
      count(*) FILTER (WHERE effective_swath=2 AND verification_status NOT IN ('verified_remediated'))::int AS s2,
      count(*) FILTER (WHERE effective_swath=3 AND verification_status NOT IN ('verified_remediated'))::int AS s3,
      count(*) FILTER (WHERE effective_swath=4 AND verification_status NOT IN ('verified_remediated'))::int AS s4,
      count(*) FILTER (WHERE cisa_kev AND verification_status NOT IN ('verified_remediated'))::int AS kev
    FROM finding_risk ${where}
  `, params)).rows[0];
  await db.query("INSERT INTO risk_snapshots (id, scope, total_open_risk, swath1_count, swath2_count, swath3_count, swath4_count, kev_open_count) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    [randomUUID(), scope, row.total, row.s1, row.s2, row.s3, row.s4, row.kev]);
}

export async function getRiskConfig(db: Awaited<ReturnType<typeof riskScoringDatabase>>): Promise<{ weights: RiskWeights; swathThresholds: SwathThresholds }> {
  const row = (await db.query("SELECT weights, swath_thresholds FROM risk_config WHERE id=1")).rows[0];
  if (!row) return { weights: DEFAULT_RISK_WEIGHTS, swathThresholds: DEFAULT_SWATH_THRESHOLDS };
  return { weights: row.weights, swathThresholds: row.swath_thresholds };
}

export async function saveRiskConfig(db: Awaited<ReturnType<typeof riskScoringDatabase>>, weights: RiskWeights, swathThresholds: SwathThresholds, actor: string): Promise<void> {
  await db.query(`INSERT INTO risk_config (id, weights, swath_thresholds, updated_by) VALUES (1,$1,$2,$3)
    ON CONFLICT (id) DO UPDATE SET weights=$1, swath_thresholds=$2, updated_at=now(), updated_by=$3`,
    [JSON.stringify(weights), JSON.stringify(swathThresholds), actor]);
}
