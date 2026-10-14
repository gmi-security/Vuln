// Offline audit helpers. Never imported by the application or used for publication.
export const pairKey = (device, cve) => JSON.stringify([device, cve]);
const open = status => ['Open', 'In Remediation'].includes(status);
const bump = (target, key) => { target[key] = (target[key] ?? 0) + 1; };
const legacySeverity = value => ({CRITICAL:'Critical',HIGH:'High',MEDIUM:'Medium',LOW:'Low'})[value] ?? 'Info';

export function createComparison(sourceRows, devices, sourceRun, publishedRun) {
  const source = new Map(), seen = new Set(), sourceCves = new Set(), sourceDevices = new Set();
  const result = {
    generationMatches: sourceRun === publishedRun, sourceInstances: 0, sourceDeviceCvePairs: 0,
    matchedPairs: 0, missingPairs: 0, duplicatePlatformPairs: 0,
    matchedStatuses: {}, matchedInactive: 0, matchedOlderGeneration: 0,
    severityDifferences: 0, scoreDifferences: 0, assessmentDifferencesWithOtherSources: 0,
    retainedRecordsAbsentFromSource: 0, absentStatuses: {}, absentClosureEvidence: {},
    absentOpenClosureEvidence: {}, absentOpenActive: 0, absentOpenOlderGeneration: 0,
  };
  for (const row of sourceRows) {
    const key = pairKey(row.device, row.cve);
    if (source.has(key)) throw new Error('Source aggregation contains duplicate pairs');
    source.set(key, row); result.sourceInstances += Number(row.instances);
    sourceCves.add(row.cve);sourceDevices.add(row.device);
  }
  result.sourceDeviceCvePairs = source.size;
  result.sourceUniqueCves=sourceCves.size;result.sourceAffectedDevices=sourceDevices.size;
  return {
    add(row) {
      if (!row.device) return;
      const key = pairKey(row.device, row.cve), current = source.get(key);
      if (seen.has(key)) result.duplicatePlatformPairs++;
      seen.add(key);
      if (current) {
        bump(result.matchedStatuses, row.status);
        if (row.active !== true) result.matchedInactive++;
        if (row.run !== sourceRun) result.matchedOlderGeneration++;
        const severityDiff = row.severity !== legacySeverity(current.severity);
        const scoreDiff = Number(row.cvss) !== Number(current.cvss ?? 0);
        if (severityDiff) result.severityDifferences++;
        if (scoreDiff) result.scoreDifferences++;
        if ((severityDiff || scoreDiff) && row.seenBy?.some(s => s !== 'defender'))
          result.assessmentDifferencesWithOtherSources++;
      } else {
        result.retainedRecordsAbsentFromSource++;
        bump(result.absentStatuses, row.status);
        const heartbeat = Date.parse(devices.get(row.device) ?? ''), observed = Date.parse(row.observed ?? '');
        const evidence = !devices.has(row.device) ? 'device-absent'
          : !Number.isFinite(heartbeat) || !Number.isFinite(observed) ? 'unknown-heartbeat-or-observation'
          : heartbeat < observed ? 'heartbeat-before-observation' : 'heartbeat-at-or-after-observation';
        bump(result.absentClosureEvidence,evidence);
        if(open(row.status)){
          bump(result.absentOpenClosureEvidence,evidence);
          if(row.active===true)result.absentOpenActive++;
          if(row.run!==sourceRun)result.absentOpenOlderGeneration++;
        }
      }
    },
    finish() {
      for (const key of source.keys()) if (seen.has(key)) result.matchedPairs++;
      result.missingPairs = source.size - result.matchedPairs;
      // This checks only current source pairs, not retained history, risk or complete platform parity.
      result.currentSourceProjectionMatches = result.generationMatches && result.missingPairs === 0 &&
        result.duplicatePlatformPairs === 0 && result.matchedInactive === 0 && result.matchedOlderGeneration === 0 &&
        result.severityDifferences === 0 && result.scoreDifferences === 0;
      return result;
    },
  };
}

export function createPlatformTotals() {
  const cves = new Set(), assets = new Set();
  const result = {records:0, statuses:{}, connectors:{}, openRemediation:0, openEndpoint:0,
    openWeb:0, openExposure:0, openSeverity:{}, uniqueOpenEndpointCves:0, openEndpointAssetKeys:0, defenderEvidence:0};
  return {
    add(row) {
      result.records++; bump(result.statuses,row.status); bump(result.connectors,row.connector);
      if(row.device) result.defenderEvidence++;
      if(!open(row.status)) return;
      if(['spiderfoot','artemis'].includes(row.connector)){result.openExposure++;return;}
      result.openRemediation++; bump(result.openSeverity,row.severity);
      if(['burp','zap'].includes(row.connector)){result.openWeb++;return;}
      result.openEndpoint++;
      if(/^CVE-\d{4}-\d{4,19}$/i.test(row.cve)) cves.add(row.cve);
      if(row.asset) assets.add(row.asset);
    },
    finish(){result.uniqueOpenEndpointCves=cves.size;result.openEndpointAssetKeys=assets.size;return result;},
  };
}
