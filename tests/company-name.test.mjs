// node --experimental-vm-modules tests/company-name.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/company-name.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext } }).outputText;
const { normalizeCompanyName, findNearDuplicateCompanyName } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);

const roster = [
  { id: "CO-147284", name: "Atlas Healthcare Partners" },
  { id: "CO-9150", name: "GMI Scans" },
];

test("findNearDuplicateCompanyName catches a whole-word prefix match in either direction", () => {
  assert.equal(findNearDuplicateCompanyName("Atlas HealthCare", roster)?.id, "CO-147284");
  assert.equal(findNearDuplicateCompanyName("Atlas Healthcare Partners LLC", roster)?.id, "CO-147284");
});

test("findNearDuplicateCompanyName does not flag an exact (post-normalization) match as a duplicate", () => {
  assert.equal(findNearDuplicateCompanyName("Atlas Healthcare Partners", roster), undefined);
  assert.equal(findNearDuplicateCompanyName("  ATLAS   healthcare Partners", roster), undefined);
});

test("findNearDuplicateCompanyName requires a word boundary, not just a substring (GCON vs GCONSULTING must not match)", () => {
  const withGcon = [{ id: "CO-1", name: "GCON" }];
  assert.equal(findNearDuplicateCompanyName("GCONSULTING", withGcon), undefined);
  assert.equal(findNearDuplicateCompanyName("GCON Inc.", withGcon)?.id, "CO-1");
});

test("findNearDuplicateCompanyName ignores unrelated names and respects excludeId", () => {
  assert.equal(findNearDuplicateCompanyName("Openworks", roster), undefined);
  assert.equal(findNearDuplicateCompanyName("Atlas HealthCare", roster, "CO-147284"), undefined);
});

test("normalizeCompanyName still folds whitespace/Unicode/smart-punctuation variants", () => {
  assert.equal(normalizeCompanyName("Atlas  Healthcare’s   Partners"), normalizeCompanyName("atlas healthcare's partners"));
});
