# Save and reader reliability rollout

Approved scope: release request-held platform views when responses finish or abort; freeze scoped saves before borrowing a database connection; refresh reporting only for affected customers. Restore the reviewed connector mutation scopes with these protections, then deploy and measure.

## Constraints

- Keep customer isolation, complete committed generations, SQL authority fencing, cancellation and fail-closed persistence.
- Keep scheduled connector imports and saved-tile settings; no automatic ticket creation.
- Preserve operator files, environment and existing ticket drafts. Use a branch and PR before production.
- Do not change digest format or storage schema. Reader bucket loading remains conservative; request cleanup removes the demonstrated retention without introducing another read protocol.

## Work and verification

1. Add failing HTTP lifecycle tests, then release request view references on finish/close/error while preserving active streaming reads. Verify with the isolated PostgreSQL retention reproduction.
2. Reinstate scoped connector mutations and frozen delta preparation. Verify concurrent changes persist on the subsequent save, stale writers and cancellation still fail, and failed preparation never starts a transaction.
3. Before writes, obtain old owners of actually changed/deleted rows and combine with frozen new owners. Rehash only those customer/bucket pairs, using the existing company/bucket/order index. Company edits retain conservative full reporting refresh. Verify output against independent full digest generation, including moves, deletes and unrelated customers.
4. Run targeted and full tests, actual PostgreSQL tests, TypeScript, Linux production/worker builds, and an independent whole-change review. Fix material issues before merging.
5. Merge, stage complete artifacts, deploy with existing runtime settings, and perform bounded live import/read validation. Check persistence, counts, ticket references, child process identity and memory. Retain previous artifacts for code rollback.

## Status

- Implementation started from main `90da990`.
- Implemented all three changes. Request lifecycle regression: 9 passed. Reporting/persistence regression group: 23 passed. Connector scope group: 78 passed.
- Linux full suite: 1,003 passed, 7 optional database tests skipped, 0 failed. Separate actual PostgreSQL run: 51 passed, 0 skipped. Platform persistence integration: 22 checks passed, including 30,001 synthetic inserts, transaction rollback, restart, ownership moves and digest parity.
- TypeScript and Linux Next.js, summary-worker and reporting-worker builds passed.
- Actual handler plus pooled PostgreSQL connections: zero of three old generations retained after responses or later connection reuse; prior handler retained all three. No production data was changed by this reproduction.
- Independent whole-change review: no blocking findings. Full-bucket reader refresh cost remains; representative live memory validation is required after deployment.
- Production rollout and live import validation are next.
