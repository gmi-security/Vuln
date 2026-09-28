import { patchTicketDatabase } from "./patch-ticket-store";
import { customerFalconTenantIds } from "./reporting-tenant-scope";
import { atlasFalconReviewPacket, ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";
import { ensureHydrated, getCompany } from "./store";

// appCompanyId is only ever set on a group's packet at persist time -- either
// from an explicit customer selection, or (its only other source) the Atlas
// tenant-CID fallback below, keyed on ATLAS_CROWDSTRIKE_TENANT_IDS as it was
// configured at that moment. A group persisted before that env var was set,
// or via the shared/unscoped "Build consolidated patch plan" tiles, has it
// permanently missing from its stored packet even after the env var is
// fixed -- which is also why it shows "CrowdStrike tenant <cid>" instead of
// a real customer name in the review queue, and why auto-create's per-
// customer filter never matches it. Re-evaluates the same fallback against
// the *current* config for every still-pending draft missing it. Safe to
// call repeatedly -- it only ever touches rows still missing appCompanyId.
export async function backfillAppCompanyId(): Promise<{ updated: number }> {
  const db = await patchTicketDatabase();
  const rows = (await db.query(`
    SELECT id, tenant_id, packet->>'source' AS source FROM patch_group_ticket_requests
    WHERE state='prepared' AND packet->>'appCompanyId' IS NULL
  `)).rows as { id: string; tenant_id: string; source: string | null }[];
  if (!rows.length) return { updated: 0 };
  const verifiedTenantIds = customerFalconTenantIds(ATLAS_REPORTING_COMPANY_ID, process.env.ATLAS_CROWDSTRIKE_TENANT_IDS);
  if (!verifiedTenantIds.length) return { updated: 0 };
  await ensureHydrated();
  const companyName = getCompany(ATLAS_REPORTING_COMPANY_ID)?.name ?? null;
  let updated = 0;
  for (const row of rows) {
    const packet = atlasFalconReviewPacket({ source: row.source === "stored-findings" ? "stored-findings" as const : undefined, tenantId: row.tenant_id }, verifiedTenantIds);
    if (!packet.appCompanyId) continue; // this tenant isn't the verified Atlas CID -- leave it alone
    await db.query(`UPDATE patch_group_ticket_requests SET packet = packet || jsonb_build_object('appCompanyId',$2::text,'companyName',$3::text), updated_at = now() WHERE id=$1`,
      [row.id, packet.appCompanyId, companyName]);
    updated++;
  }
  return { updated };
}
