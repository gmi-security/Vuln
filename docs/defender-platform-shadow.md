# Defender platform finding shadow contract, version 2

Version 2 retains the lossless version-1 field layout and adds the original snapshot order to finding identity rows. This preserves stable priority ties for the saved read model described in `docs/defender-shadow-reads.md`. Earlier version-1 measurements below remain historical; existing disposable version-1 projections must be rebuilt, not silently reused.

This is the first storage migration prototype for published platform findings. It copies the existing customer-scoped Defender findings into a separate disposable database, verifies reconstruction of every field and preserves the old database unchanged. It is not an active ingestion path, a replacement source of truth or a complete schema for all providers.

## Why this starts from published findings

The October 9 restored Footprint source import contains 212,921 current device/CVE pairs. Its published platform snapshot also retains 2,970 older open findings and 72,987 resolved records. Re-importing current vendor records alone would discard those records, along with potentially important workflow decisions and assessments.

This contract copies every published finding with Defender evidence for the explicitly selected customer, including correlated findings whose primary connector may be another scanner. A record naming Defender as its connector but missing Defender identity/evidence fails the build. Other customers and unrelated findings are excluded. This is customer-scoped legacy evidence, not verification of a new upstream tenant binding.

## Data layout

Explicit migration: `docs/sql/defender-platform-shadow.sql`. Builder and verification helpers: `lib/db/defender-platform-shadow.mjs`.

| Table | Responsibility |
| --- | --- |
| `defender_shadow_generations` | Customer, versioned projection ID, matching published/import generation, snapshot-save timestamp and building/verified/failed state |
| `defender_shadow_findings` | Existing finding ID, issue/CVE key, legacy asset key and connector; remaining descriptive/context fields in a compatibility JSON object |
| `defender_shadow_workflow` | Existing status, assignment, first/last seen and resolved time |
| `defender_shadow_assessments` | Saved platform severity, CVSS, real-risk score and risk priority; no scoring recalculation |
| `defender_shadow_evidence` | Stable Defender device/CVE identity, source generation, observation time, active flag, nullable vendor CVSS and remaining source details |

All primary and foreign keys include customer and projection. A unique source device/CVE key rejects ambiguous duplicate pairs inside a customer generation. Retained evidence has no foreign key to source-run tables because older source data can legitimately be pruned before the corresponding platform workflow/history is removed.

Legacy asset identifiers are preserved, not relabelled as verified platform asset IDs. Workflow timestamps retain their original text representation. Unknown vendor CVSS stays null; existing platform zero defaults remain as recorded. Additional scores, threat enrichment, other-source labels, remediation text, optional flags and future fields stay in compatibility details. Promoted fields are removed from those detail objects rather than storing a second complete legacy record.

This deliberately does not normalize every remediation, asset, enrichment or ticket entity yet. The compatibility fields permit lossless migration while later contracts are developed. Existing external ticket/history tables and their references are not copied, deleted or rewritten by this step; finding IDs remain unchanged for future linkage validation.

## Build and failure behavior

The builder requires two dedicated, already connected clients. It checks that both use the private recovery cluster with networking disabled, that the source is the named restore or a test source, and that the target is a separate generated `vuln2_shadow_test_*` database. There is no environment loading, application initializer, runtime route, worker startup or automatic schema migration.

1. Pin a read-only repeatable-read source snapshot. Verify the customer is known and non-demo, the sharded layout is supported, and the retained completed Defender generation and connection revision match the saved publication marker.
2. Create a new building generation in the disposable target. Never replace a prior verified generation.
3. Read bounded snapshot buckets and split writes into 500-record transactions. A source keepalive between batches preserves the pinned snapshot during target work.
4. Reconstruct each batch from the four normalized record tables and compare every JSON field with the original. A difference rolls back that batch and fails the generation. Composite-key lookups keep this verification bounded even before table statistics reflect a new bulk load.
5. Verify all four table counts, refresh narrow-column statistics in the disposable target, then mark the generation verified. This changes no application/current-source pointer.

Limits: 20,000 records per source bucket, 500,000 selected findings, 15-second statements, two-second target lock waits, a five-minute deadline checked between operations and a 60-second source idle-transaction timeout. The test harness adds a six-minute process limit. A failed run may retain completed batches in its failed disposable generation; the verification reader rejects it. A retry uses a new projection ID. There is no production retry queue, retention policy or activation path for these prototype tables.

## Validation

Local tests cover immutable projection, preserved workflow and source-null values, resolved/inactive evidence, malformed records, invalid scores and customer rejection. PostgreSQL fixtures exercise complete record reconstruction, scoped reads and foreign keys, interruption after a committed batch, preservation of a previous verified generation, duplicate source identities, connection revision drift and retry isolation.

The full restored-data run passed: all 288,878 published Footprint records reconstructed field by field, with 215,891 Open, 72,987 Resolved and 2,970 older active open findings retained. It took 150,528 ms over 618 batches. Node peak RSS was 197 MiB; disposable target tables/indexes used 660,504,576 bytes (about 630 MiB, including small fixture overhead). The status/severity validation aggregate took 1,012 ms and remains an offline diagnostic, not a fast page reader. CVE/asset distinct counts in its rows are per group and cannot be summed across groups.

Three contract tests and eleven existing comparison/legacy-semantics tests passed, as did five PostgreSQL fixture scenarios and the separate restored-data validation. The final fixture run also checked malformed demo metadata and rejection of a verified generation without a count. No host identities, raw findings, credentials or ticket content are printed; validation errors omit database row details and assertion payloads. Temporary databases were dropped and the private cluster stopped.

Run local contract tests with:

```sh
node --test tests/defender-platform-shadow.test.mjs
```

The PostgreSQL harness requires the established private restore setup and explicit socket path:

```sh
node --max-old-space-size=768 tests/defender-platform-shadow-postgres.mjs \
  /home/codex/vuln-recovery/baseline-uVic9i/restore-6hXR1M/socket \
  --with-restored-defender
```

It creates and drops separate fixture databases, including the full-data target. The caller must stop the private cluster in cleanup and remove any strictly identified test databases left by a process kill. Never direct this at production.

## Remaining gates

This verifies storage fidelity, not a new risk formula or end-to-end reporting/ticket behavior. It does not implement incremental source updates, asset correlation, an active generation pointer, history measurement migration, an authoritative writer, customer authorization routes or other-provider migration.

Saved summary and paginated reads now have an isolated implementation and validation harness described in `docs/defender-shadow-reads.md`. Keep the shadow isolated until lifecycle, source authority, CVE detail/patch-input parity, ticket linkage, failure recovery and rollout/rollback gates are satisfied.
