// node --experimental-vm-modules --test tests/risk-scoring.test.mjs
//
// Exercises the pure risk-scoring engine (lib/risk-scoring.ts): the three
// worked scenarios from the RBVM spec (KEV+exposed beats plain-CVSS,
// low-EPSS-internal loses to it, and a lower-CVSS actively-exploited finding
// can outscore a higher-CVSS quiet one -- risk is not synonymous with CVSS),
// plus Swath threshold mapping, emergency elevation overrides, and score
// determinism/configurable weights.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

function loader(overrides = {}) {
  const cache = new Map();
  async function load(path) {
    path = resolve(path);
    if (cache.has(path)) return cache.get(path);
    const code = ts.transpileModule(await readFile(path, "utf8"), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    const mod = new SourceTextModule(code, { identifier: path }); cache.set(path, mod);
    await mod.link(async (name) => {
      if (overrides[name]) { const values = overrides[name]; return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); }); }
      if (name.startsWith(".")) return load(resolve(dirname(path), `${name}.ts`));
      if (name.startsWith("@/")) return load(resolve(".", `${name.slice(2)}.ts`));
      const values = await import(name);
      return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
    });
    return mod;
  }
  return async (path) => { const mod = await load(path); await mod.evaluate(); return mod.namespace; };
}

const load = loader();
const NOW = "2026-09-30T00:00:00.000Z";

function baseInput(overrides = {}) {
  return {
    cve: "CVE-2026-00000", cvss: 9.8, epssProbability: 0.02, epssPercentile: 0.3,
    cisaKev: false, knownExploit: false, activeExploitation: false, ransomwareAssociation: false,
    publishedAt: "2026-09-01T00:00:00.000Z", patchAvailable: true, repeatedDetection: false, widespreadExposure: false,
    internetExposed: false, assetCriticality: "Normal", assetType: "server", production: false,
    healthcareIomt: false, criticalBusinessApp: false, clientDesignatedCritical: false, now: NOW,
    ...overrides,
  };
}

test("scenario 1: CVSS 9.8 + KEV + internet-facing critical server scores very high and lands in Swath 1", async () => {
  const { calculateRiskScore, calculateSwath } = await load("lib/risk-scoring.ts");
  const input = baseInput({
    cvss: 9.8, epssProbability: 0.9, epssPercentile: 0.98, cisaKev: true, knownExploit: true,
    internetExposed: true, assetCriticality: "Crown Jewel", production: true, clientDesignatedCritical: true,
  });
  const result = calculateRiskScore(input);
  assert.ok(result.total >= 800, `expected >=800, got ${result.total}`);
  assert.ok(result.reasons.includes("CISA Known Exploited Vulnerability"));
  assert.ok(result.reasons.includes("Internet-facing asset"));
  const swath = calculateSwath(input, result.total);
  assert.equal(swath.effectiveSwath, 1);
});

test("scenario 2: CVSS 9.8 but low EPSS, internal noncritical workstation, no exploit scores substantially lower than scenario 1", async () => {
  const { calculateRiskScore } = await load("lib/risk-scoring.ts");
  const highRisk = calculateRiskScore(baseInput({
    cvss: 9.8, epssProbability: 0.9, epssPercentile: 0.98, cisaKev: true, knownExploit: true,
    internetExposed: true, assetCriticality: "Crown Jewel", production: true, clientDesignatedCritical: true,
  }));
  const quietFinding = calculateRiskScore(baseInput({
    cvss: 9.8, epssProbability: 0.001, epssPercentile: 0.05, cisaKev: false, knownExploit: false,
    internetExposed: false, assetCriticality: "Normal", assetType: "workstation", production: false,
  }));
  assert.ok(quietFinding.total < highRisk.total * 0.6, `expected substantially lower, got ${quietFinding.total} vs ${highRisk.total}`);
});

test("scenario 3: CVSS 7.5 + KEV + active exploitation + internet-facing can outscore a quiet CVSS 9.8 -- risk is not synonymous with CVSS", async () => {
  const { calculateRiskScore } = await load("lib/risk-scoring.ts");
  const exploitedModerate = calculateRiskScore(baseInput({
    cvss: 7.5, epssProbability: 0.85, epssPercentile: 0.95, cisaKev: true, activeExploitation: true,
    knownExploit: true, internetExposed: true, assetCriticality: "High", production: true,
  }));
  const quietCritical = calculateRiskScore(baseInput({
    cvss: 9.8, epssProbability: 0.001, epssPercentile: 0.05, cisaKev: false, knownExploit: false,
    internetExposed: false, assetCriticality: "Normal", assetType: "workstation", production: false,
  }));
  assert.ok(exploitedModerate.total > quietCritical.total,
    `expected exploited CVSS-7.5 (${exploitedModerate.total}) to outscore quiet CVSS-9.8 (${quietCritical.total})`);
});

test("score is capped at 1000 even with every factor maxed", async () => {
  const { calculateRiskScore } = await load("lib/risk-scoring.ts");
  const result = calculateRiskScore(baseInput({
    cvss: 10, epssProbability: 1, epssPercentile: 1, cisaKev: true, knownExploit: true, activeExploitation: true,
    ransomwareAssociation: true, internetExposed: true, assetType: "domain_controller", assetCriticality: "Crown Jewel",
    production: true, healthcareIomt: true, criticalBusinessApp: true, clientDesignatedCritical: true,
    publishedAt: "2020-01-01T00:00:00.000Z", patchAvailable: false, repeatedDetection: true, widespreadExposure: true,
  }));
  assert.ok(result.total <= 1000);
  assert.equal(result.technical + result.exploitLikelihood + result.threatActivity + result.assetContext + result.additionalContext, result.total);
});

test("the breakdown is fully explainable -- component scores sum to the total, and reasons are never empty for a risky finding", async () => {
  const { calculateRiskScore } = await load("lib/risk-scoring.ts");
  const result = calculateRiskScore(baseInput({ cisaKev: true, internetExposed: true, epssProbability: 0.5 }));
  assert.equal(result.technical + result.exploitLikelihood + result.threatActivity + result.assetContext + result.additionalContext, result.total);
  assert.ok(result.reasons.length > 0);
});

test("Swath thresholds: 800+/600-799/400-599/0-399 map to Swath 1/2/3/4 without elevation triggers", async () => {
  const { calculateSwath } = await load("lib/risk-scoring.ts");
  const quiet = { cisaKev: false, activeExploitation: false, ransomwareAssociation: false, internetExposed: false, assetType: "server", production: false, clientDesignatedCritical: false };
  assert.equal(calculateSwath(quiet, 850).effectiveSwath, 1);
  assert.equal(calculateSwath(quiet, 650).effectiveSwath, 2);
  assert.equal(calculateSwath(quiet, 450).effectiveSwath, 3);
  assert.equal(calculateSwath(quiet, 100).effectiveSwath, 4);
  assert.equal(calculateSwath(quiet, 450).calculatedSwath, calculateSwath(quiet, 450).effectiveSwath);
});

test("Swath override: KEV + internet-facing elevates to Swath 1 even when the numeric score alone would land lower", async () => {
  const { calculateSwath } = await load("lib/risk-scoring.ts");
  const result = calculateSwath({ cisaKev: true, activeExploitation: false, ransomwareAssociation: false, internetExposed: true, assetType: "server", production: false, clientDesignatedCritical: false }, 450);
  assert.equal(result.calculatedSwath, 3);
  assert.equal(result.effectiveSwath, 1);
  assert.match(result.elevationReason, /CISA KEV/);
});

test("Swath override: active exploitation on a critical asset elevates to Swath 1", async () => {
  const { calculateSwath } = await load("lib/risk-scoring.ts");
  const result = calculateSwath({ cisaKev: false, activeExploitation: true, ransomwareAssociation: false, internetExposed: false, assetType: "server", production: true, clientDesignatedCritical: false }, 350);
  assert.equal(result.effectiveSwath, 1);
  assert.match(result.elevationReason, /Active exploitation/);
});

test("Swath override: ransomware association on an exposed production asset elevates to Swath 1", async () => {
  const { calculateSwath } = await load("lib/risk-scoring.ts");
  const result = calculateSwath({ cisaKev: false, activeExploitation: false, ransomwareAssociation: true, internetExposed: true, assetType: "server", production: true, clientDesignatedCritical: false }, 200);
  assert.equal(result.effectiveSwath, 1);
  assert.match(result.elevationReason, /Ransomware/);
});

test("Swath override: Tier-0 identity infrastructure (domain controller, client-critical) elevates to Swath 1", async () => {
  const { calculateSwath } = await load("lib/risk-scoring.ts");
  const result = calculateSwath({ cisaKev: false, activeExploitation: false, ransomwareAssociation: false, internetExposed: false, assetType: "domain_controller", production: false, clientDesignatedCritical: true }, 300);
  assert.equal(result.effectiveSwath, 1);
  assert.match(result.elevationReason, /Tier-0 identity/);
});

test("recalculation is deterministic -- the same input always yields the same score", async () => {
  const { calculateRiskScore } = await load("lib/risk-scoring.ts");
  const input = baseInput({ cisaKev: true, epssProbability: 0.4 });
  const a = calculateRiskScore(input), b = calculateRiskScore(input);
  assert.deepEqual(a, b);
});

test("weights are configurable -- a custom weight set changes the score without editing the engine", async () => {
  const { calculateRiskScore, DEFAULT_RISK_WEIGHTS } = await load("lib/risk-scoring.ts");
  const input = baseInput({ cisaKev: true, internetExposed: true });
  const defaultResult = calculateRiskScore(input);
  const heavierThreat = { ...DEFAULT_RISK_WEIGHTS, threatActivity: { ...DEFAULT_RISK_WEIGHTS.threatActivity, kev: DEFAULT_RISK_WEIGHTS.threatActivity.kev + 50 } };
  const customResult = calculateRiskScore(input, heavierThreat);
  assert.ok(customResult.total > defaultResult.total);
});

test("a null CVSS does not crash scoring and lands at a neutral technical score", async () => {
  const { calculateRiskScore } = await load("lib/risk-scoring.ts");
  const result = calculateRiskScore(baseInput({ cvss: null }));
  assert.ok(Number.isFinite(result.technical));
  assert.ok(result.technical > 0);
});
