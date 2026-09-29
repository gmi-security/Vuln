const asIso = value => value == null ? null : new Date(value).toISOString();

async function readLegacy(client, result) {
  const legacy = (await client.query(`SELECT
    jsonb_array_length(CASE WHEN jsonb_typeof(data->'companies') = 'array' THEN data->'companies' ELSE '[]'::jsonb END) AS companies,
    jsonb_array_length(CASE WHEN jsonb_typeof(data->'folders') = 'array' THEN data->'folders' ELSE '[]'::jsonb END) AS folders,
    jsonb_array_length(CASE WHEN jsonb_typeof(data->'scans') = 'array' THEN data->'scans' ELSE '[]'::jsonb END) AS scans,
    jsonb_array_length(CASE WHEN jsonb_typeof(data->'findings') = 'array' THEN data->'findings' ELSE '[]'::jsonb END) AS findings,
    jsonb_array_length(CASE WHEN jsonb_typeof(data->'assets') = 'array' THEN data->'assets' ELSE '[]'::jsonb END) AS assets,
    jsonb_array_length(CASE WHEN jsonb_typeof(data->'compensatingControls') = 'array' THEN data->'compensatingControls' ELSE '[]'::jsonb END) AS controls,
    jsonb_array_length(CASE WHEN jsonb_typeof(data->'identityAliases') = 'array' THEN data->'identityAliases' ELSE '[]'::jsonb END) AS aliases,
    updated_at FROM vuln_snapshot WHERE id = 1`)).rows[0];
  if (legacy) {
    result.source = "legacy";
    result.collections = {
      companies: Number(legacy.companies), folders: Number(legacy.folders),
      scans: Number(legacy.scans), findings: Number(legacy.findings),
      assets: Number(legacy.assets), compensatingControls: Number(legacy.controls),
      identityAliases: Number(legacy.aliases),
    };
    result.updatedAt = asIso(legacy.updated_at);
  }
}

export async function collectSnapshotInventory(client) {
  await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  try {
    const tables = (await client.query(`SELECT
      to_regclass('public.vuln_store')::text AS snapshot_table,
      to_regclass('public.vuln_snapshot')::text AS legacy_table,
      to_regclass('public.spotlight_import_records')::text AS spotlight_table`)).rows[0];
    const result = {
      snapshotTablePresent: Boolean(tables.snapshot_table),
      legacyTablePresent: Boolean(tables.legacy_table),
      spotlightTablePresent: Boolean(tables.spotlight_table),
      source: "none",
      updatedAt: null,
      bucketCount: 0,
      collections: {},
      malformedBuckets: [],
    };
    if (!result.snapshotTablePresent) {
      if (result.legacyTablePresent) await readLegacy(client, result);
      await client.query("COMMIT");
      return result;
    }
    const keys = (await client.query("SELECT key FROM vuln_store ORDER BY key")).rows;
    if (keys.length === 0 && result.legacyTablePresent) {
      await readLegacy(client, result);
      await client.query("COMMIT");
      return result;
    }
    if (keys.length > 0) result.source = "sharded";
    for (const { key } of keys) {
      if (key === "meta") continue;
      const match = /^([a-zA-Z][a-zA-Z0-9]*):\d+$/.exec(key);
      if (!match) {
        result.malformedBuckets.push(key);
        continue;
      }
      const row = (await client.query(`SELECT CASE WHEN jsonb_typeof(data) = 'array'
        THEN jsonb_array_length(data) ELSE NULL END AS items
        FROM vuln_store WHERE key = $1`, [key])).rows[0];
      if (row?.items == null) {
        result.malformedBuckets.push(key);
        continue;
      }
      result.collections[match[1]] = (result.collections[match[1]] ?? 0) + Number(row.items);
      result.bucketCount++;
    }
    if (keys.some(row => row.key === "meta")) {
      const meta = (await client.query(`SELECT
        jsonb_array_length(CASE WHEN jsonb_typeof(data->'compensatingControls') = 'array' THEN data->'compensatingControls' ELSE '[]'::jsonb END) AS controls,
        jsonb_array_length(CASE WHEN jsonb_typeof(data->'identityAliases') = 'array' THEN data->'identityAliases' ELSE '[]'::jsonb END) AS aliases
        FROM vuln_store WHERE key = 'meta'`)).rows[0];
      result.collections.compensatingControls = Number(meta?.controls ?? 0);
      result.collections.identityAliases = Number(meta?.aliases ?? 0);
    }
    const timestamp = (await client.query("SELECT MAX(updated_at) AS updated_at FROM vuln_store")).rows[0]?.updated_at;
    result.updatedAt = asIso(timestamp);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  }
}
