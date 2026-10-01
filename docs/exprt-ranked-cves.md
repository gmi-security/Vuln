# Open CVEs ranked by ExPRT

After merge and deployment, an existing CrowdStrike-connected dashboard receives a saved **Open CVEs — ranked by ExPRT** tile at the bottom. It is not a preset in the Add Query form. It starts with the top 100 rated CVEs, uses the existing 50-row pagination, and refreshes daily. Edit supports up to 500 CVEs.

The table sorts by CrowdStrike ExPRT rating: Critical, High, Medium, then Low. Within a rating it sorts by unique affected devices descending, then CVE ID for a stable tie-break. ExPRT is a categorical rating, not the app's custom numeric risk score. CVSS severity and score appear in separate columns.

Columns: CVE, ExPRT rating, affected devices, open findings, CVSS severity, CVSS base score, and CISA KEV. Existing CVE details, patch preparation, page-scoped consolidated plans, and full-result CSV export remain available.

The saved filter is `status:['open','reopen']`, including suppressed findings. Unrated CVEs and non-CVE findings are excluded from ranking. Each tenant/device identity is counted once per CVE; distinct finding instances are counted separately.

## Collection and limits

The client requests `cve.exprt_rating` bands in descending priority from CrowdStrike's Spotlight API. It finishes the entire current band before choosing top rows, and skips lower bands once the table is full. This avoids ranking an arbitrary first page. EPSS enrichment is not needed for this table and is not requested.

Existing limits remain: at most 250,000 findings per collected band and the existing overall collection deadline. Incomplete pagination, API failures, inconsistent ratings, or exceeded limits fail the refresh rather than presenting partial counts as complete. Previous successful cached data is retained. CrowdStrike collection is not an atomic snapshot of all finding changes.

If a band exceeds the limit, narrow the saved FQL scope. Displaying more CVEs can require additional bands and therefore more collection work. Pagination controls the number of rendered rows; it does not reduce the source data required for accurate affected-device ranking.

## Installation

The database initializer installs the tile when the dashboard has a CrowdStrike connection. It preserves the existing visible order, including legacy tiles with null `display_order`, and appends the new tile. The installation transaction uses the same advisory lock as dashboard layout changes. A fixed ID preserves user edits and soft deletion; subsequent restarts do not recreate a deleted tile.

No credentials, existing filters, or existing query results are replaced. No additional database table is required. The feature must be merged into `main` and deployed before it appears; pushing the feature branch alone does not change production.

Sources: [CrowdStrike Spotlight API and supported ExPRT filter](https://github.com/CrowdStrike/falconpy/wiki/Spotlight-Vulnerabilities), [CrowdStrike explanation of ExPRT rating categories](https://www.crowdstrike.com/en-us/blog/falcon-exposure-management-ai-driven-risk-prioritization-shows-what-to-fix-first/).
