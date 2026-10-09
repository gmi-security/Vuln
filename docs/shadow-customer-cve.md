# Disabled customer CVE adapter

`lib/db/shadow-customer-cve.mjs` combines the verified Defender shadow reader with saved enrichment and ticket context. It has no application route, production caller, environment initializer, schema initializer, vendor client or ticket writer. It remains an offline comparison adapter.

## Connections and flow

```text
Explicit enable + trusted customer/projection binding
  -> existing customer resolver supplied by the caller
  -> shadow client: complete bounded CVE evidence
  -> application client: saved cve_enrichment
  -> dashboard/ticket client: saved references and exact exclusions
  -> public detail object + separate server-only preparation inputs
```

The three clients are passed explicitly. Enrichment belongs to the application database; tickets belong to the dashboard database. They may be different databases. No assumption that both configurations share a server or database is introduced.

`createShadowCustomerCveReader` is disabled unless `enabled` is the boolean `true`. Its bindings are copied from trusted configuration at construction. The request supplies only a customer and CVE; a supplied projection or source cannot override configuration. Only an explicit Defender binding is supported. A duplicate binding, unsupported source, unknown customer, demo customer, mismatched identity or invalid projection fails. A binding selects a comparison snapshot; it does not establish tenant ownership or activate the proposed connector registry. Authentication remains the eventual route's responsibility, using existing guards.

The source read completes before any contextual lookup, so a CVE absent from the selected customer's verified projection does not become a global enrichment/ticket search. This retains the published-Defender-cohort label. It must not replace the complete customer view where other providers contribute findings.

## Output and compatibility

| Value | Behavior |
| --- | --- |
| `detail` | Existing customer-CVE panel fields plus explicit cohort, generation and enrichment-availability metadata |
| `detail.enrichment` | Saved CVSS, EPSS, KEV, active-exploitation evidence/source and update timestamp for this CVE; saved finding scores are not recalculated |
| `detail.tickets` | Latest 100 group-request references whose packet belongs to the selected customer and includes the CVE; `moreTickets` signals additional references |
| `preparation.findings` | Complete bounded findings from the shadow reader, retaining original IDs and remediation evidence |
| `preparation.excluded` | A Set of exact `[companyId, asset, CVE]` JSON identity keys for the selected findings |

Serialize only `detail` to a panel response. `preparation` stays on the server; it is not a ticket packet, persisted request or authorization to send anything. Ticket reference ordering matches newest preparation first, with request ID as a deterministic tie-breaker where the existing service left ties unspecified.

Reference visibility and exclusion eligibility are intentionally different. The existing panel shows group-request history, including prepared, failed or closed entries. Exclusion lookup considers both legacy single requests and group requests in creating, uncertain or created state with `closed=false`. Closed/prepared requests do not suppress devices. The existing legacy single-request history does not consistently carry an app company ID; those candidate packets must be checked by exact stored identity. Only matching selected-customer asset/CVE keys leave the boundary. Foreign packet contents and unrelated identities are never returned. This preserves existing cross-target exclusion semantics; it does not add a ConnectWise environment filter.

Global `cve_enrichment` is shared CVE evidence, attached only after customer-scoped finding membership succeeds. MISP/OpenCTI evidence already saved in its source/detail fields is retained. This does not introduce a new feed poll, evidence expiry policy, default tile or expanded threat-intelligence collection.

## Missing data and limits

- Missing enrichment table: null enrichment with `unavailable`; existing table without this CVE: null with `not-recorded`.
- Missing ticket tables: error, not an empty reference list or empty exclusions. No schema is created on a read.
- Missing or unsupported source: error before context lookup; no source API or global/default-customer fallback.
- Reads use read-only repeatable-read transactions with five-second statement limits, two-second lock waits and 15-second idle transaction limits.
- Each contextual result is measured in PostgreSQL before full transfer and limited to 8 MiB. More than 10,000 candidate single or group packets for the CVE fails rather than returning partial exclusions. This count includes candidate packets from other customers where legacy identity matching is necessary.
- Invalid scope containers fail. Malformed legacy single-host identity strings establish no match, preserving existing behavior.

Shadow evidence, enrichment and ticket context use separate transactions, potentially across databases. The response is not a single cross-database atomic snapshot. Ticket state can change after a read. Existing draft/send locking, duplicate checks and revalidation must remain in force; this adapter cannot replace them. Production throughput and ticket-history scale are not established by small fixture timings.

## Validation

```text
node --experimental-vm-modules --test tests/shadow-customer-cve.test.mjs tests/customer-cve.test.mjs tests/defender-shadow-cve.test.mjs
```

Six adapter contract tests plus the 15 existing CVE tests pass. The private PostgreSQL runner's `--with-customer-cve` flag builds a disposable source database and a separate shadow/ticket database. It compares every existing public detail field with the actual `readCustomerCve` function, exact exclusion keys with the actual legacy exclusion function, and complete pure patch output. The legacy loader blocks initializers, live store access and mutations.

Eight adapter scenarios cover parity and the reference limit, no matching source, missing enrichment, absent CVE enrichment, missing ticket schema, an actual payload larger than 8 MiB, more than 10,000 candidate packets, and malformed containers. Foreign-customer and different-CVE references, closed/prepared exclusions, uncertain/creating requests and request projection overrides are included. All passed alongside five base-projection scenarios. No real ticket records or production source tables were read or changed.
