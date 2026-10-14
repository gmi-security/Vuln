import assert from "node:assert/strict";
import test from "node:test";

const runtime = await import("../lib/runtime-routing.mjs").catch(error => {
  if (error.code === "ERR_MODULE_NOT_FOUND") return {};
  throw error;
});

test("every API mutation goes to the writer except the auth subtree", () => {
  assert.equal(typeof runtime.shouldForwardToWorker, "function");
  for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
    for (const path of ["/api/companies", "/api/admin/resync", "/api/elastic-vulnerabilities/ingest", "/api/authz", "/api/companies?id=1"]) {
      assert.equal(runtime.shouldForwardToWorker(method, path), true, `${method} ${path}`);
    }
    assert.equal(runtime.shouldForwardToWorker(method, "/api/auth/callback/github"), false);
    assert.equal(runtime.shouldForwardToWorker(method, "/api/auth"), false);
    assert.equal(runtime.shouldForwardToWorker(method, "/login"), false);
  }
});

test("job status and stateful GETs remain with their writer", () => {
  assert.equal(typeof runtime.shouldForwardToWorker, "function");
  for (const path of [
    "/api/elastic-dashboard/customer-sync?companyId=a",
    "/api/defender/connections", "/api/tidal/import", "/api/automate/import", "/api/crowdstrike/import",
    "/api/connectors/sync-all", "/api/crowdstrike/debug", "/api/crowdstrike/spotlight-import",
  ]) {
    for (const method of ["GET", "HEAD"]) assert.equal(runtime.shouldForwardToWorker(method, path), true, `${method} ${path}`);
  }
});

test("committed reporting reads and unrelated prefix lookalikes stay responsive on web", () => {
  assert.equal(typeof runtime.shouldForwardToWorker, "function");
  for (const path of [
    "/api/companies", "/api/report/1", "/api/scans", "/api/elastic-dashboard/reporting",
    "/api/elastic-dashboard", "/api/elastic-dashboard/", "/api/elastic-dashboard/jobs/123",
    "/api/elastic-dashboard/patch-tickets/123", "/api/elastic-dashboard/patch-group-tickets/job-status",
    "/api/elastic-dashboard/connections/crowdstrike",
    "/api/elastic-dashboard/top-fixes", "/api/elastic-dashboard/customer-tiles", "/api/elastic-dashboard/customer-connectors",
    "/api/elastic-dashboard/patch-tickets-extra", "/api/tidal/import-file", "/api/crowdstrike/health",
    "/api/elastic-dashboard/jobs-old", "/api/companies?redirect=/api/elastic-dashboard/jobs/1",
  ]) assert.equal(runtime.shouldForwardToWorker("GET", path), false, path);
  assert.equal(runtime.shouldForwardToWorker("OPTIONS", "/api/companies"), false);
});

test("routing normalizes URL paths without allowing a caller supplied destination", () => {
  assert.equal(typeof runtime.shouldForwardToWorker, "function");
  assert.equal(runtime.shouldForwardToWorker("POST", "/api%2fcompanies"), true);
  assert.equal(runtime.shouldForwardToWorker("POST", "/api/auth/../companies"), true);
  assert.equal(runtime.shouldForwardToWorker("GET", "http://untrusted.test/api/crowdstrike/import"), true);
});
