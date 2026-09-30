const COLLECTIONS = ["companies", "folders", "scans", "findings", "assets", "compensatingControls", "identityAliases"];
const ORPHAN_KINDS = ["folderCompany", "scanCompany", "scanFolder", "assetCompany", "findingCompany", "findingScan", "controlCompany"];
const SAMPLE_LIMIT = 20;
const counts = () => Object.create(null);

function count(map, key) {
  const label = key == null || key === "" ? "(missing)" : String(key);
  map[label] = (map[label] ?? 0) + 1;
}

function noteIssue(issue, id) {
  issue.count++;
  if (issue.samples.length < SAMPLE_LIMIT) issue.samples.push(id);
}

export async function auditLegacyBuckets(buckets) {
  const report = {
    bucketCount: 0,
    collections: Object.fromEntries(COLLECTIONS.map(name => [name, { rows: 0, malformed: 0, duplicateIds: 0, duplicateSamples: [] }])),
    byCompany: counts(),
    facets: { findingConnector: counts(), findingStatus: counts(), findingSeverity: counts(), scanConnector: counts(), assetSource: counts() },
    orphans: Object.fromEntries(ORPHAN_KINDS.map(name => [name, { count: 0, samples: [] }])),
    maxNumericSuffix: 0,
    legacyCounter: null,
  };
  const seen = Object.fromEntries(COLLECTIONS.map(name => [name, new Set()]));
  const references = [];

  function addRecord(collection, item) {
    const stats = report.collections[collection];
    if (!Array.isArray(item) || item.length !== 2 || typeof item[0] !== "string" || !item[0] ||
        (collection !== "identityAliases" && (item[1] == null || typeof item[1] !== "object" || Array.isArray(item[1]) || item[1].id !== item[0])) ||
        (collection === "identityAliases" && typeof item[1] !== "string")) {
      stats.malformed++;
      return;
    }
    const [id, value] = item;
    stats.rows++;
    if (seen[collection].has(id)) {
      stats.duplicateIds++;
      if (stats.duplicateSamples.length < SAMPLE_LIMIT && !stats.duplicateSamples.includes(id)) stats.duplicateSamples.push(id);
    } else {
      seen[collection].add(id);
    }
    if (collection !== "identityAliases") {
      const suffix = /-(\d+)$/.exec(id);
      if (suffix) report.maxNumericSuffix = Math.max(report.maxNumericSuffix, Number(suffix[1]));
    }
    if (collection === "identityAliases") return;
    const companyId = collection === "companies" ? id : value.companyId;
    if (companyId) {
      const company = report.byCompany[companyId] ??= counts();
      company[collection] = (company[collection] ?? 0) + 1;
    }
    if (collection === "findings") {
      count(report.facets.findingConnector, value.connector);
      count(report.facets.findingStatus, value.status);
      count(report.facets.findingSeverity, value.severity);
    } else if (collection === "scans") count(report.facets.scanConnector, value.connector);
    else if (collection === "assets") count(report.facets.assetSource, value.source);
    if (collection !== "companies") references.push({ collection, id, companyId, folderId: value.folderId, scanId: value.scanId });
  }

  for await (const { key, data } of buckets) {
    if (key === "meta") {
      if (data && typeof data === "object" && !Array.isArray(data)) {
        if (Number.isSafeInteger(data.counter)) report.legacyCounter = data.counter;
        for (const name of ["compensatingControls", "identityAliases"]) {
          const items = data[name];
          if (Array.isArray(items)) for (const item of items) addRecord(name, item);
          else if (items !== undefined) report.collections[name].malformed++;
        }
      }
      continue;
    }
    const collection = key.split(":")[0];
    if (!COLLECTIONS.includes(collection)) continue;
    report.bucketCount++;
    if (!Array.isArray(data)) {
      report.collections[collection].malformed++;
      continue;
    }
    for (const item of data) addRecord(collection, item);
  }

  for (const ref of references) {
    const checks = [];
    if (ref.collection === "folders") checks.push(["folderCompany", ref.companyId, "companies"]);
    if (ref.collection === "scans") {
      checks.push(["scanCompany", ref.companyId, "companies"]);
      if (ref.folderId) checks.push(["scanFolder", ref.folderId, "folders"]);
    }
    if (ref.collection === "assets") checks.push(["assetCompany", ref.companyId, "companies"]);
    if (ref.collection === "findings") {
      checks.push(["findingCompany", ref.companyId, "companies"]);
      checks.push(["findingScan", ref.scanId, "scans"]);
    }
    if (ref.collection === "compensatingControls") checks.push(["controlCompany", ref.companyId, "companies"]);
    for (const [kind, target, targetCollection] of checks) {
      if (!target || !seen[targetCollection].has(target)) noteIssue(report.orphans[kind], ref.id);
    }
  }
  return report;
}
