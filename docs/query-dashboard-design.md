# Query Dashboard design

The Query Dashboard uses the approved black/charcoal layout with GMI red accents.
It is one shared dashboard, with no workspace picker. The dedicated shell variant
uses top navigation; other application pages retain their existing sidebar.

- Compact metric strips replace nested number cards. Severity uses the existing
  app palette. Percentage bars appear only for a result composed of severity
  columns; they describe the returned findings, not a second live API total.
- Metric and chart tiles use a responsive two-column grid. Tables and metric
  strips with four or more columns span the full width. Existing saved order is
  retained, and narrow screens stack tiles.
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

Live release verification is recorded below after deployment.
