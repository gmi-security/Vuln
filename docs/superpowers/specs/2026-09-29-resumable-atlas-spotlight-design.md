# Resumable Atlas Spotlight Import

## Purpose

Atlas has roughly 2.1 million Spotlight vulnerability records. The current importer queries and hydrates records in one pass, but a failed request or app restart abandons every stored row and starts over. Three production attempts stopped before promotion. The next import must retain verified progress across process failures while preserving the rule that only a complete generation becomes active.

## Scope

Use the existing Atlas customer binding (`CO-147284`) and `DATABASE_URL` database. Preserve each CrowdStrike source ID and full hydrated payload. Keep the reporting page, the in-memory scanner store, the unnamed primary tenant, and ConnectWise behavior unchanged. Support future named customer tenants through the same company binding; do not hardcode Atlas in the import engine.

## Flow

1. Create or resume one database generation for the selected tenant. A previous generation with the new checkpoint format can resume; legacy partial generations remain inactive and are pruned only when safe.
2. Discovery queries Spotlight IDs in bounded 400-ID pages. Each page's IDs and continuation cursor commit in one database transaction. A process restart resumes at the committed cursor. If CrowdStrike rejects a saved cursor, abandon that discovery attempt and start discovery from the first page in a new generation. CrowdStrike documents `after` pagination but does not guarantee cursor validity across restarts.
3. A completed discovery pass freezes the candidate ID set in PostgreSQL. Hydration then reads candidate IDs in stable key order, fetches their full source records in bounded batches, and commits the records and last hydrated ID atomically. A restart reuses this ID set and resumes at the last committed ID; it does not repeat already committed hydration work.
4. Promotion requires the ID count and stored source-record count to match exactly in one transaction. Missing or mismatched entity IDs fail visibly and preserve the previous active generation. No partial generation is shown as complete.
5. The run phase, cursor, ID count, stored count, and last error are durable. A repeat POST resumes an interrupted or failed generation. GET should report this database status when process-local status has reset.

## Operational limits

- An invalid discovery cursor can require repeating the ID-only discovery pass. Previously hydrated records are not discarded by a failure in the hydration phase.
- The Spotlight source changes during long imports; this represents the set of IDs returned by one completed discovery traversal, with full details fetched afterward. It is not a transactional snapshot of CrowdStrike's live estate. If an ID cannot be hydrated, the run fails rather than silently omitting it.
- The import still runs in the web process and requires an operator POST to resume after a process restart. Moving it to a dedicated worker is a later deployment change.
- The additive schema must first be exercised against an isolated restored database before production use. The live branch is not a substitute for that gate.

## Verification

Use tests that stop after a committed discovery page, resume and finish discovery; stop after a committed hydration batch, resume and skip that batch; reject an expired cursor and restart only discovery; reject missing hydrated IDs; ensure an interrupted generation cannot become active; and ensure a prior active generation stays visible throughout. Run the full suite, typecheck and production build. On a restored database, exercise the schema and one interrupted import before the Atlas production test.
