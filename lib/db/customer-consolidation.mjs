// Pure planner for the two operator-approved duplicate customers. Callers own
// the database transaction and must verify its snapshot before applying it.
const fail = message => { throw Error(message); };
const clone = value => structuredClone(value);
const label = value => typeof value === 'string' ? value.trim().toLowerCase() : '';
const collection = (buckets, kind) => [...buckets].filter(([key]) => key.startsWith(`${kind}:`)).flatMap(([, rows]) => rows);
const index = (buckets, kind) => new Map(collection(buckets, kind));
const requireUnique = (rows, kind) => {
  const ids = rows.map(([id]) => id);
  if (ids.some(id => typeof id !== 'string' || !id) || new Set(ids).size !== ids.length) fail(`Invalid or duplicate ${kind} identity.`);
};
const sourceIn = (value, sourceIds) => typeof value === 'string' && sourceIds.some(id => value.includes(id));

export function planCustomerConsolidation(snapshot, mappings) {
  if (!(snapshot instanceof Map) || !Array.isArray(mappings) || mappings.length !== 2) fail('Two approved customer mappings required.');
  const buckets = clone(snapshot);
  const pairs = new Map();
  for (const pair of mappings) {
    if (!pair || !/^CO-\d+$/.test(pair.sourceId) || !/^CO-\d+$/.test(pair.destinationId) ||
        pair.sourceId === pair.destinationId || !pair.sourceName || !pair.destinationName || pairs.has(pair.sourceId)) fail('Invalid customer mapping.');
    pairs.set(pair.sourceId, pair);
  }
  if (new Set([...pairs.values()].map(pair => pair.destinationId)).size !== 2) fail('Destination customers must be distinct.');
  for (const kind of ['companies','folders','scans','findings','assets']) requireUnique(collection(buckets,kind),kind);
  const companies = index(buckets,'companies');
  for (const pair of pairs.values()) {
    if (companies.get(pair.sourceId)?.name !== pair.sourceName || companies.get(pair.destinationId)?.name !== pair.destinationName)
      fail('Customer identity or name changed since approval.');
  }
  const folderRows = collection(buckets,'folders'), folders = index(buckets,'folders'), folderMapping = new Map();
  const lineage = { companies:[], folders:[], assets:[] };
  for (const pair of pairs.values()) {
    lineage.companies.push({source:clone(companies.get(pair.sourceId)),destinationId:pair.destinationId});
    for (const [id,folder] of folderRows.filter(([,f])=>f.companyId===pair.sourceId)) {
      const matches = folderRows.filter(([,f])=>f.companyId===pair.destinationId && label(f.name)===label(folder.name));
      if (matches.length>1) fail('Ambiguous destination folder.');
      if (matches.length && label(folder.name)!=='general') fail('Unreviewed folder-name collision.');
      const destinationId = matches[0]?.[0] ?? id;
      folderMapping.set(id,destinationId);
      lineage.folders.push({source:clone(folder),destinationId});
    }
  }
  for (const [key,rows] of buckets) if (key.startsWith('folders:')) buckets.set(key,rows.flatMap(([id,folder])=>{
    const pair=pairs.get(folder.companyId);
    if (!pair) return [[id,folder]];
    if (folderMapping.get(id)!==id) return [];
    return [[id,{...folder,companyId:pair.destinationId}]];
  }));
  const movedFolders=index(buckets,'folders');
  for (const [key,rows] of buckets) if (key.startsWith('scans:')) buckets.set(key,rows.map(([id,scan])=>{
    const pair=pairs.get(scan.companyId);
    if (!pair) return [id,scan];
    if (!scan.folderId || !folders.has(scan.folderId) || folders.get(scan.folderId).companyId!==pair.sourceId)
      fail('Source scan has a missing or cross-customer folder.');
    const folderId=folderMapping.get(scan.folderId),folder=movedFolders.get(folderId);
    if (!folder || folder.companyId!==pair.destinationId) fail('Scan folder remap failed.');
    return [id,{...scan,companyId:pair.destinationId,companyName:pair.destinationName,folderId,folderName:folder.name}];
  }));
  const scans=index(buckets,'scans');
  for (const [key,rows] of buckets) if (key.startsWith('findings:')) buckets.set(key,rows.map(([id,finding])=>{
    const pair=pairs.get(finding.companyId);
    if (!pair) return [id,finding];
    const scan=scans.get(finding.scanId);
    if (!scan || scan.companyId!==pair.destinationId) fail('Source finding has a missing or cross-customer scan.');
    return [id,{...finding,companyId:pair.destinationId,companyName:pair.destinationName}];
  }));
  const allAssets=collection(buckets,'assets');
  const crowdstrikeObservations=new Map();
  for (const [key,rows] of buckets) if (key.startsWith('assets:')) buckets.set(key,rows.flatMap(([id,asset])=>{
    const pair=pairs.get(asset.companyId);
    if (!pair) return [[id,asset]];
    const matches=allAssets.filter(([,other])=>other.companyId===pair.destinationId && label(other.identifier)===label(asset.identifier));
    if (matches.length>1) fail('Ambiguous destination asset identity.');
    if (matches.length) {
      const [destinationId,destination]=matches[0];
      if (asset.source!=='crowdstrike' || destination.source!=='automate' || !label(asset.hostname) ||
          label(asset.hostname)!==label(destination.hostname))
        fail('Unreviewed cross-provider asset collision.');
      if (destination.crowdstrikeObservation || crowdstrikeObservations.has(destinationId))
        fail('CrowdStrike observation collision requires review.');
      crowdstrikeObservations.set(destinationId,Object.fromEntries(Object.entries({
        assetId:id,externalId:asset.externalId,identifier:asset.identifier,hostname:asset.hostname,
        ipAddresses:asset.ipAddresses,os:asset.os,owner:asset.owner,tags:asset.tags,
        exposure:asset.exposure,criticality:asset.criticality,lastSynced:asset.lastSynced,
      }).filter(([,value])=>value!==undefined)));
      lineage.assets.push({source:clone(asset),destinationId,destinationBefore:clone(destination)});
      return [];
    }
    return [[id,{...asset,companyId:pair.destinationId,companyName:pair.destinationName}]];
  }));
  for (const [key,rows] of buckets) if (key.startsWith('assets:')) buckets.set(key,rows.map(([id,asset])=>
    crowdstrikeObservations.has(id) ? [id,{...asset,crowdstrikeObservation:crowdstrikeObservations.get(id)}] : [id,asset]));
  for (const [key,rows] of buckets) if (key.startsWith('companies:')) buckets.set(key,rows.filter(([id])=>!pairs.has(id)));
  const meta=buckets.get('meta');
  if (!meta || !Array.isArray(meta.identityAliases) || meta.customerConsolidation) fail('Missing aliases or customer consolidation already applied.');
  const aliases=new Map();
  for (const edge of meta.identityAliases) {
    if (!Array.isArray(edge) || edge.length!==2 || typeof edge[0]!=='string' || typeof edge[1]!=='string') fail('Malformed identity alias.');
    const remap=value=>{for (const pair of pairs.values()) if (value.startsWith(`${pair.sourceId}::`)) return pair.destinationId+value.slice(pair.sourceId.length);return value;};
    const [from,to]=edge.map(remap);
    if (from.split('::')[0]!==to.split('::')[0]) fail('Cross-customer identity alias.');
    if (aliases.has(from) && aliases.get(from)!==to) fail('Conflicting identity alias after remap.');
    aliases.set(from,to);
  }
  for (const start of aliases.keys()) {
    const seen=new Set();let current=start;
    while (aliases.has(current)) {if (seen.has(current)) fail('Identity alias cycle after remap.');seen.add(current);current=aliases.get(current);}
  }
  meta.identityAliases=[...aliases];
  meta.customerConsolidation={version:1,mappings:[...pairs.values()].map(({sourceId,destinationId})=>({sourceId,destinationId}))};
  const sourceIds=[...pairs.keys()];
  const removedAssetIds=lineage.assets.map(({source})=>source.id);
  if (removedAssetIds.length) {
    const reference=new RegExp(removedAssetIds.map(id=>id.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('|'));
    for (const kind of ['folders','scans','findings'])
      for (const [,record] of collection(snapshot,kind)) if (reference.test(JSON.stringify(record)))
        fail(`Removed asset ID is referenced by ${kind}.`);
    const retainedMeta=clone(meta);delete retainedMeta.customerConsolidation;
    if (reference.test(JSON.stringify(retainedMeta))) fail('Removed asset ID is referenced by metadata.');
  }
  for (const [key,value] of buckets) if (key!=='meta' && sourceIn(JSON.stringify(value),sourceIds)) fail(`Unhandled legacy customer reference in ${key}.`);
  // Meta can contain scheduler keys. Refuse to guess their meaning; the caller
  // must deliberately migrate each discovered reference before applying.
  const rest=clone(meta);delete rest.customerConsolidation;
  if (sourceIn(JSON.stringify(rest),sourceIds)) fail('Unhandled legacy customer reference in metadata.');
  const folderIndex=index(buckets,'folders'),scanIndex=index(buckets,'scans');
  const orphans={scanFolder:0,findingScan:0};
  for (const scan of scanIndex.values()) if (!folderIndex.has(scan.folderId) || folderIndex.get(scan.folderId).companyId!==scan.companyId) orphans.scanFolder++;
  for (const [,finding] of collection(buckets,'findings')) if (!scanIndex.has(finding.scanId) || scanIndex.get(finding.scanId).companyId!==finding.companyId) orphans.findingScan++;
  if (orphans.scanFolder || orphans.findingScan) fail('Post-merge orphan or cross-customer reference.');
  for (const kind of ['scans','findings']) {
    const before=index(snapshot,kind),after=index(buckets,kind);
    if (before.size!==after.size || [...before.keys()].some(id=>!after.has(id))) fail(`${kind} identity loss.`);
  }
  for (const kind of ['companies','folders','scans','findings','assets']) {
    const before=index(snapshot,kind),after=index(buckets,kind);
    for (const [id,record] of before) if (!pairs.has(record.companyId) && !pairs.has(id) && !crowdstrikeObservations.has(id) &&
      JSON.stringify(after.get(id))!==JSON.stringify(record)) fail(`Unrelated ${kind} record changed.`);
  }
  if (index(snapshot,'assets').size-index(buckets,'assets').size!==lineage.assets.length ||
      index(snapshot,'folders').size-index(buckets,'folders').size!==lineage.folders.filter(row=>row.source.id!==row.destinationId).length)
    fail('Unexpected asset or folder deletion.');
  return {buckets,lineage,report:{mappings:[...pairs.values()],foldersRemapped:lineage.folders.length,assetCollisions:lineage.assets.length,orphans}};
}
