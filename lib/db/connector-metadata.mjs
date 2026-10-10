// Dedicated, already-connected pg clients only. No pools/schema initializers or
// application hydration: those can create tables, start jobs or load all findings.
const LIMIT = 10000;
async function bounded(client, sql, params = []) {
  const rows = (await client.query(`${sql} LIMIT ${LIMIT + 1}`, params)).rows;
  if (rows.length > LIMIT) throw new Error('Connector metadata limit exceeded; no partial preview produced.');
  return rows;
}
async function present(client, name) {
  return !!(await client.query('SELECT to_regclass($1)::text AS name', [`public.${name}`])).rows[0].name;
}
async function readOnly(client, fn) {
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try {
    await client.query("SET LOCAL statement_timeout='15s'");
    await client.query("SET LOCAL lock_timeout='2s'");
    await client.query("SET LOCAL idle_in_transaction_session_timeout='30s'");
    const result = await fn();
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  }
}
const validateCompany = row => {
  if (row.valid === false || typeof row.id !== 'string' || !row.id || typeof row.name !== 'string' || !row.name ||
      (row.isDemo != null && typeof row.isDemo !== 'boolean')) throw new Error('Invalid saved company metadata.');
  return { id: row.id, name: row.name, isDemo: row.isDemo === true };
};
// The platform serializes its Maps as [id, value] entries, not plain objects.
const companyEntry = entry => {
  if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string' || entry[1]?.id !== entry[0])
    throw new Error('Invalid saved company metadata.');
  return validateCompany(entry[1]);
};

async function applicationCompanies(client) {
    let companies = [], companyStorage = 'none';
    const sharded = await present(client, 'vuln_store');
    const hasShards = sharded && (await client.query('SELECT 1 FROM public.vuln_store LIMIT 1')).rows.length > 0;
    if (hasShards) {
      // Match assembleSnapshot: an array in meta takes precedence over buckets.
      const meta = (await client.query("SELECT data->'companies' AS companies FROM public.vuln_store WHERE key='meta'")).rows[0]?.companies;
      if (meta !== undefined && meta !== null) {
        if (!Array.isArray(meta) || meta.length > LIMIT) throw new Error('Invalid companies in snapshot metadata.');
        companies = meta.map(companyEntry);
        companyStorage = 'sharded-meta';
      } else {
        const bad = await client.query("SELECT key FROM public.vuln_store WHERE key ~ '^companies:[0-9]+$' AND jsonb_typeof(data) IS DISTINCT FROM 'array' LIMIT 1");
        if (bad.rows.length) throw new Error('Invalid company snapshot bucket.');
        companies = (await bounded(client, `SELECT c->1->>'id' AS id,c->1->>'name' AS name,c->1->'isDemo' AS "isDemo",
          CASE WHEN jsonb_typeof(c)='array' THEN jsonb_array_length(c)=2 AND jsonb_typeof(c->0)='string'
            AND c->>0=c->1->>'id' ELSE false END AS valid
          FROM public.vuln_store s CROSS JOIN LATERAL jsonb_array_elements(
            CASE WHEN s.key ~ '^companies:[0-9]+$' THEN s.data ELSE '[]'::jsonb END) c
          WHERE s.key ~ '^companies:[0-9]+$'`)).map(validateCompany);
        companyStorage = 'sharded';
      }
    } else if (await present(client, 'vuln_snapshot')) {
      const row = (await client.query("SELECT data->'companies' AS companies FROM public.vuln_snapshot WHERE id=1")).rows[0];
      if (row) {
        if (!Array.isArray(row.companies) || row.companies.length > LIMIT) throw new Error('Invalid legacy companies.');
        companies = row.companies.map(companyEntry);
        companyStorage = 'legacy';
      }
    }
    return { companies, companyStorage };
}
export async function readSavedApplicationCompanies(client) {
  return readOnly(client, async () => (await applicationCompanies(client)).companies);
}
export async function readApplicationConnectorMetadata(client) {
  return readOnly(client, async () => {
    const { companies, companyStorage } = await applicationCompanies(client);
    const defenderTable = await present(client, 'defender_connections');
    const defender = defenderTable ? await bounded(client, `SELECT company_id AS "companyId",tenant_id AS "tenantId",revision
      FROM public.defender_connections ORDER BY company_id`) : [];
    const spotlightTable = await present(client, 'spotlight_import_current');
    const spotlight = spotlightTable ? await bounded(client, `SELECT c.tenant_key AS "companyId",c.run_id::text AS "runId",r.status
      FROM public.spotlight_import_current c LEFT JOIN public.spotlight_import_runs r ON r.id=c.run_id ORDER BY c.tenant_key`) : [];
    return { companies, defender, spotlight, coverage: { companyStorage, defenderTable, spotlightTable } };
  });
}

export async function readDashboardConnectorMetadata(client) {
  return readOnly(client, async () => {
    const connections = [];
    const elasticTable = await present(client, 'elastic_dashboard_connection');
    if (elasticTable) connections.push(...await bounded(client,
      "SELECT 'elastic' AS source,revision FROM public.elastic_dashboard_connection WHERE id=1"));
    const sourcesTable = await present(client, 'dashboard_source_connections');
    if (sourcesTable) connections.push(...await bounded(client, 'SELECT source,revision FROM public.dashboard_source_connections ORDER BY source'));
    const tilesTable = await present(client, 'elastic_dashboard_queries');
    const tiles = [];
    if (tilesTable) {
      const hasDeleted = (await client.query(`SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='elastic_dashboard_queries' AND column_name='deleted_at'`)).rows.length > 0;
      const rows = await bounded(client, `SELECT id,revision,COALESCE(definition->>'source','elastic') AS source,
        definition ? 'companyId' AS "hasOwner",definition->'companyId' AS "companyId"
        FROM public.elastic_dashboard_queries ${hasDeleted ? 'WHERE deleted_at IS NULL' : ''} ORDER BY id`);
      for (const row of rows) {
        if (row.hasOwner && row.companyId !== null && typeof row.companyId !== 'string') throw new Error('Invalid saved tile owner.');
        tiles.push({ id: row.id, revision: row.revision, source: row.source,
          ...(row.hasOwner ? { companyId: row.companyId } : {}) });
      }
    }
    const deliveryTable = await present(client, 'patch_connectwise_connection');
    const delivery = deliveryTable ? await bounded(client, 'SELECT revision FROM public.patch_connectwise_connection WHERE id=1') : [];
    return { connections, tiles, delivery, coverage: { elasticTable, sourcesTable, tilesTable, deliveryTable } };
  });
}
