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

// Routing (lib/group-auto-create.ts's patch_customer_routing) is only ever
// learned the moment a ticket is *confirmed created*, from that ticket's own
// row -- and only if that row's packet already had appCompanyId at that
// exact moment. Every Atlas ticket created before backfillAppCompanyId
// existed had no appCompanyId on its packet when it was created, so none of
// them ever taught the routing table anything, no matter how many of them
// now sit in ConnectWise as real, confirmed, correctly-routed tickets. This
// seeds it directly from the most recently created one instead of waiting
// on a brand new ticket -- same trust boundary as the routing-learning step
// itself (a human explicitly picked this routing when they created that
// ticket), just applied retroactively. Never overwrites an existing row: a
// human-established routing from a normal ticket creation always wins.
export async function backfillCustomerRouting(): Promise<{ seeded: boolean }> {
  const db = await patchTicketDatabase();
  const existing = await db.query("SELECT 1 FROM patch_customer_routing WHERE app_company_id=$1", [ATLAS_REPORTING_COMPANY_ID]);
  if (existing.rows.length) return { seeded: false };
  const verifiedTenantIds = customerFalconTenantIds(ATLAS_REPORTING_COMPANY_ID, process.env.ATLAS_CROWDSTRIKE_TENANT_IDS);
  if (!verifiedTenantIds.length) return { seeded: false };
  const row = (await db.query(`
    SELECT company_id, (routing->>'boardId')::int AS board_id, (routing->>'teamId')::int AS team_id
    FROM patch_group_ticket_requests
    WHERE state='created' AND ticket_id IS NOT NULL AND company_id IS NOT NULL AND routing->>'boardId' IS NOT NULL
      AND lower(tenant_id) = ANY($1::text[])
    ORDER BY updated_at DESC LIMIT 1`, [verifiedTenantIds])).rows[0] as { company_id: number; board_id: number; team_id: number | null } | undefined;
  if (!row) return { seeded: false };
  await db.query(`INSERT INTO patch_customer_routing(app_company_id,company_id,board_id,team_id,updated_at,updated_by)
    VALUES($1,$2,$3,$4,now(),$5) ON CONFLICT(app_company_id) DO NOTHING`,
    [ATLAS_REPORTING_COMPANY_ID, row.company_id, row.board_id, row.team_id, "backfill-from-existing-ticket"]);
  return { seeded: true };
}
