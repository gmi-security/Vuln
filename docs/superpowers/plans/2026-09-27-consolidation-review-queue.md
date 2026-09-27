# Consolidation Review Queue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Save consolidation candidates in a durable review queue so an analyst can inspect, approve, and explicitly send a ConnectWise ticket.

**Architecture:** Keep generated candidates in the existing Postgres ticket request table. Add a separate review state and audit trail, expose packet details in the queue, and require approval in the server-side ticket creation path. ConnectWise remains the only outbound write and occurs only after the reviewer submits the ticket form.

**Tech Stack:** Next.js, React, PostgreSQL, Node.js.

**Spec:** User request in this chat: automatically generate a queue for review and allow a person to send approved work via ConnectWise.

## Global Constraints

- Customer reports can contain several connector sources; do not silently treat all findings as CrowdStrike data.
- Do not send a ConnectWise ticket automatically.
- No `.env` or credentials are available in this checkout.

## Review Focus

- A draft cannot create a ticket before approval.
- A dismissed draft cannot create a ticket.
- A reviewer can inspect the saved remediation and affected devices after leaving the consolidation dialog.
- Repeated generation does not flood the queue with duplicate pending work.
- A ConnectWise company must match the reviewed customer before a ticket is sent.

---

### Task 1: Durable review state

**Files:** `lib/patch-ticket-store.ts`, `lib/patch-group-ticket-store.ts`, `lib/patch-group-ticket-types.ts`, `app/api/elastic-dashboard/patch-group-tickets/[id]/route.ts`.

- [x] Add review fields to the existing request table and summary.
- [x] Add approve, dismiss, and reopen transitions with audit records.
- [x] Enforce approval in `createGroupTicket` inside the row lock.
- [ ] Verify transitions and duplicate behavior with focused tests where dependencies are available.

### Task 2: Persistent queue interface

**Files:** `components/PatchReviewQueue.tsx`, `components/ConnectWiseGroupTicket.tsx`, `components/ElasticQueryDashboard.tsx`, `components/PatchConsolidationPanel.tsx`.

- [x] List saved drafts on Reporting, ordered by date and review status.
- [x] Fetch the saved packet when a reviewer opens a row; show remediation, CVEs, device count, and CSV.
- [x] Present approval before the existing editable ConnectWise ticket form.
- [x] Keep ticket creation explicit and show its saved state afterward.

### Task 3: Automatic generation

**Files:** generation path to be chosen after connector scope is confirmed.

- [x] Build candidates from stored open findings across connectors, independent of a query dialog.
- [x] Add an hourly generation check and idempotent insert so the queue does not fill with repeats.
- [x] Confirm customer-to-ConnectWise ownership before tickets from stored findings can be sent.

Local verification remains open because this checkout has no installed Node dependencies or service credentials.
