# Query Dashboard design

The Query Dashboard uses the approved black/charcoal layout with GMI red accents.
It is one shared dashboard, with no workspace picker. The dedicated shell variant
uses top navigation; other application pages retain their existing sidebar.

- Compact metric strips replace nested number cards. Severity uses the existing
  app palette. Percentage bars appear only for a result composed of severity
  columns; they describe the returned findings, not a second live API total.
- Metric and chart tiles use responsive wrapping rows. Tables and metric
  strips with four or more columns span the full width. Existing saved order is
  retained, and narrow screens stack tiles. Lone smaller tiles grow to fill a row
  when the next tile spans the full width, avoiding empty half-rows.
- Arrange tiles enters a draft layout. Drag handles and keyboard/touch arrow
  buttons change only this draft. Save layout sends one request to the existing
  order endpoint. Cancel sends no mutation. Failed saves keep the draft available
  to retry or cancel. Background result polling retains the draft order.
- Tables have sticky headings and internal scrolling. CVE links open an accessible
  native dialog showing a snapshot of the selected row's actual returned fields.
  This does not fetch device inventory or invent affected-device names.
- Existing chart rendering, CSV export, editing, deletion confirmation, optional
  previews, source connections, refresh jobs, error states and cached results
  remain connected. No query definitions, credentials or database schemas change.

## Validation, September 24, 2026

- Six layout/browser-client regression tests passed.
- Real Chromium checks against an isolated local Next.js fixture passed: desktop
  and mobile (390px and 320px), drag and arrow arrangement, no write before Save,
  Cancel rollback, Save, a rejected Save followed by Cancel, CVE dialog/Escape,
  internal table scrolling, CSV and Add tile form. No browser runtime errors.
- Desktop/mobile screenshots were inspected. The fixture contains synthetic
  data, uses a local-only test session and mocked API writes, and is excluded
  from the repository and production build.
- ESLint cannot run because this repository has no ESLint configuration file.
  Production build/type checking and HTTP smoke checks are the release gates.
- Final production build and TypeScript checks passed. All four changed runtime
  file hashes match the isolated build copy. HTTP smoke checks passed in disabled,
  sample and empty modes, including session guards and existing routes; no test
  database was configured for this UI-only release.

## Live release

Commit `c33191fbfc5a71707550b4ecb0a69860151db450` is ACTIVE in DigitalOcean
deployment `9100517a-4b34-4f09-a653-158b47723d1c`. Live application health and
database reachability are true. A read-only database check confirms all seven
saved tiles still have results. The CVE device tile retains its 100 rows,
September 24 22:54:28 UTC refresh timestamp and no error.

Interactive checks used the isolated local fixture; no production tile was
reordered or otherwise mutated for testing.

## Readability follow-up

The user's screenshot exposed gaps from mixed half/full-width rows and small,
low-contrast supporting text. Wrapping flex rows now fill these gaps without
changing saved order. Titles are 16px, supporting labels/table text are 14px,
and captions/footers are 13px with zinc-300 contrast. Longer informational notes
move into a native Result details disclosure; stale/error/partial-result warnings
remain visible. Line and bar charts measure their container width instead of
scaling the entire SVG, keeping text readable and the line plot at 335px high.
Time ticks use shorter labels with space reserved for the last tick.

Chromium checks passed with a half-width/full-width alternating fixture: all rows
fill the available width, the line chart stays 335px tall, footer text is at least
13px, details expand, and desktop/mobile arrangement and tile actions still work.
