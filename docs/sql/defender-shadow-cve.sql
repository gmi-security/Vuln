-- Explicit disposable shadow migration only; no application initializer.
-- Keep source casing intact; customer CVE matching is case-insensitive.
CREATE INDEX IF NOT EXISTS defender_shadow_findings_cve_detail
  ON defender_shadow_findings(company_id,projection_id,upper(issue_key),legacy_order);
