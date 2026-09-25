# ConnectWise patch tickets

On Vulnerability intelligence, open **Connections**, select **ConnectWise · Patch tickets**, and enter:

The default authentication method for new connections is **CW_AUTH (encoded authorization)**. Enter the API address, Client ID, and the Base64 value from `CW_AUTH`. A `Basic ` prefix is accepted; omit the `CW_AUTH=` assignment itself. The server validates and extracts `companyID+publicKey:privateKey`, then encrypts the credentials using the same storage and sends the same Basic authorization header as separate-key mode. Saved settings never return the encoded value or keys. Leaving CW_AUTH blank preserves saved credentials only if the API address and Client ID are unchanged. Switching to this method does not change the API member's permissions or resolve a permission-denied 403.

**Company ID and separate API keys** remains available for existing connections. In that mode, enter:

- ConnectWise PSA API address (for example the appropriate regional API base ending in `/v4_6_release/apis/3.0`).
- Login company ID, identifying the ConnectWise account.
- ConnectWise integration Client ID.
- API member public and private keys.

**Test and save ConnectWise** makes a read-only service board request. It does not create a test ticket. Keys are encrypted using a purpose-specific key derived from `NEXTAUTH_SECRET` and are never returned by settings reads. Blank key fields preserve saved credentials only when the account/address/Client ID are unchanged. Preserve the server encryption secret when redeploying.

The API member needs access to read companies, service boards, board statuses and teams, and priorities; read/create service tickets; and read/upload ticket documents. Configure the member's security role in ConnectWise. This deployment has not been validated against a customer's ConnectWise account until credentials are entered and tested.

Choose routing defaults from lists fetched from ConnectWise. No board names or IDs are hardcoded. Lists support pagination, company search, and loading saved selections outside the first page. Changing a board clears its status/team. Closed or inactive selections cannot be used. Customer company is explicitly selected during each ticket review; it is distinct from the login company ID.

## Workflow

1. Click any CVE, then **Prepare patch request**. The complete CrowdStrike report is persisted as a shared draft.
2. If the report spans multiple CrowdStrike tenants, select one tenant and prepare its report. A multi-tenant report can be downloaded but cannot be sent as a customer ticket.
3. **Review ConnectWise ticket**, choose the owning company and routing, and edit the title/contents if needed.
4. **Create ConnectWise ticket** is the explicit sending action. The description contains CVE scores and recommended remediations; the asset list stays in the CSV. The CSV is attached as a private ticket document.
5. **Patch tickets** opens the shared register. CVE history also appears in its side panel. Saved reports can be reopened after the temporary preparation job expires.

All signed-in organization members retain access, consistent with the dashboard's existing permission model. Reports and ticket history are shared, not personal drafts. The register displays the latest 100 requests; each CVE has a separate latest-100 history. There is no automatic historical-ticket import or customer mapping.

## Recovery and tracking

- A database claim and unique active-scope index prevent simultaneous requests for the same CVE, company, account, and exact affected-device set. Different or overlapping device sets are not automatically merged; the review warns about existing CVE tickets.
- The ticket number is saved before CSV upload. **CSV pending** exposes an independent retry that reconciles existing documents before uploading again.
- A lost creation response produces **Check creation outcome**. Recovery looks up the unique `externalXRef` and never automatically replays ticket creation. If no ticket is found, check again or investigate in ConnectWise; the app does not offer a blind resend.
- Interrupted in-process workers become recoverable after three minutes. No permanent queue service is required, and browser polling reads only local request state.
- **Check ConnectWise status** explicitly refreshes the saved status. Closed tickets are labelled **fix unverified**: ticket closure does not prove CrowdStrike remediation. There is no scheduled ConnectWise polling in this pass.
- An account change blocks recovery/upload against the wrong ConnectWise account. A changed CrowdStrike connection requires fresh preparation before sending.
- Task-owned tables: `patch_connectwise_connection`, `patch_ticket_requests`, `patch_ticket_audit`. Schema is initialized lazily. Audit entries record actor/action/reference without credentials or report content. Persisted report snapshots include asset information for later CSV recovery.

## Validation

`node --experimental-vm-modules --test tests/connectwise-patch-tickets.test.mjs` verifies encryption/redaction, real option names and pagination, routing identity, public DNS pinning, redirect rejection, no automatic POST retries, and CSV reconciliation.

Set `PATCH_TICKET_TEST_DATABASE_URL` to an isolated local PostgreSQL database named `patch_ticket_test` to enable lifecycle tests. The test refuses non-local hosts and other database names and truncates only its task-owned test tables. It verifies simultaneous duplicate requests, retrying attachments without recreating tickets, uncertain-response reconciliation, definite rejection retries, tenant/revision guards, interrupted-worker recovery, and account isolation. External ConnectWise responses are mocked; tests never send tickets.

Browser checks cover member access, secure key fields, real-name selection, board/status reset, defaults, ticket review, CSV retry, shared history, saved report resume, mobile layout, and existing any-CVE actions. Live account permissions, board availability, and ticket creation require the user's saved ConnectWise credentials.
