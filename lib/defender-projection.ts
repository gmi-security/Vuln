import { createHash } from "node:crypto";
import type { DefenderDevice } from "./defender-client";
import type { Finding, InventoryAsset, Severity } from "./types";
import { mergeFindingAssessment, normalizeIdentifier } from "./finding-correlation";

export type DefenderFinding = {
  deviceId: string; hostname: string; cve: string; severity: string; cvss: number | null;
  firstSeen: string | null; lastSeen: string | null; remediation: string; exploitAvailable: boolean;
};
export type DefenderSnapshot = {
  companyId: string; runId: string; observedAt: string; devices: DefenderDevice[]; findings: DefenderFinding[];
};
type Asset = Omit<InventoryAsset, "openFindings">;
const id = (kind: string, ...parts: string[]) => `${kind}-${createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0,32)}`;
const key = (device: string, cve: string) => JSON.stringify([device,cve]);
const severity = (value: string): Severity => ({ CRITICAL:"Critical", HIGH:"High", MEDIUM:"Medium", LOW:"Low" } as Record<string,Severity>)[value.toUpperCase()] ?? "Info";

// Build replacements without mutating live records. Publishing is a single synchronous
// store operation after the complete, pinned database generation has been read.
export function planDefenderProjection(snapshot: DefenderSnapshot, companyName: string,
  existingFindings: Iterable<Finding>, existingAssets: Iterable<Asset>,
  score: (finding: Finding, asset: Asset | undefined) => Partial<Finding>) {
  const ownAssets = [...existingAssets].filter(a=>a.companyId === snapshot.companyId);
  const ownFindings = [...existingFindings].filter(f=>f.companyId === snapshot.companyId);
  const devices = new Map(snapshot.devices.map(d=>[d.deviceId,d]));
  for (const f of snapshot.findings) if (!devices.has(f.deviceId)) devices.set(f.deviceId,
    { deviceId:f.deviceId,hostname:f.hostname,ip:"",os:"",lastSeen:null });
  const hostnameCounts = new Map<string,number>();
  for (const d of devices.values()) {
    const name = normalizeIdentifier(d.hostname);
    hostnameCounts.set(name,(hostnameCounts.get(name) ?? 0)+1);
  }
  const assetsByName = new Map<string,Asset[]>();
  for (const a of ownAssets) for (const name of new Set([a.identifier,a.hostname].filter(Boolean).map(normalizeIdentifier))) {
    const rows = assetsByName.get(name) ?? []; rows.push(a); assetsByName.set(name,rows);
  }
  const assetChanges = new Map<string,Asset>(), deviceAssets = new Map<string,Asset>();
  const usedAssets = new Set<string>();
  const stableAssets = new Map(ownAssets.filter(a=>a.defenderDeviceId).map(a=>[a.defenderDeviceId!,a]));
  for (const d of devices.values()) {
    const stableId = id("DEF-ASSET",snapshot.companyId,d.deviceId);
    const name = normalizeIdentifier(d.hostname), matches = assetsByName.get(name) ?? [];
    // Match an unambiguous hostname inside this customer only. Never identify a
    // device using an IP (NAT/reuse), or merge two Defender device IDs.
    const stable = stableAssets.get(d.deviceId);
    let asset = stable ?? (hostnameCounts.get(name) === 1 && matches.length === 1 && !matches[0].defenderDeviceId && !usedAssets.has(matches[0].id) ? matches[0] : undefined);
    if (!asset) asset = { id:stableId, identifier:`defender:${d.deviceId}`, hostname:d.hostname,
      ipAddresses:[], companyId:snapshot.companyId, companyName, exposure:"Internal",criticality:"Normal",
      os:d.os,owner:"",tags:[],source:"defender",externalId:d.deviceId,lastSynced:snapshot.observedAt };
    else asset = { ...asset };
    if (asset.source === "defender") {
      asset.hostname = d.hostname; asset.os = d.os || asset.os; asset.lastSynced = snapshot.observedAt;
      // Only keep a private device identifier as the key; IP is display/context,
      // and is intentionally not registered as an identity alias.
      asset.ipAddresses = d.ip ? [d.ip] : [];
    }
    asset.defenderDeviceId = d.deviceId;
    usedAssets.add(asset.id); deviceAssets.set(d.deviceId,asset); assetChanges.set(asset.id,asset);
  }
  const sourceIndex = new Map<string,Finding>(), correlation = new Map<string,Finding[]>();
  for (const f of ownFindings) {
    if (f.defender) sourceIndex.set(key(f.defender.deviceId,f.cve),f);
    const k = key(normalizeIdentifier(f.asset),f.cve);
    const rows = correlation.get(k) ?? []; rows.push(f); correlation.set(k,rows);
  }
  const changes = new Map<string,Finding>(), touched = new Set<string>();
  for (const row of snapshot.findings) {
    const asset = deviceAssets.get(row.deviceId)!;
    const candidates = new Map<string,Finding>();
    // Only this device's unique hostname/identifier may corroborate another scanner.
    for (const name of [asset.identifier,...(hostnameCounts.get(normalizeIdentifier(row.hostname)) === 1 ? [row.hostname] : [])]) {
      for (const f of correlation.get(key(normalizeIdentifier(name),row.cve)) ?? [])
        if (!f.defender && f.status !== "Resolved") candidates.set(f.id,f);
    }
    const old = sourceIndex.get(key(row.deviceId,row.cve)) ?? (candidates.size === 1 ? [...candidates.values()][0] : undefined);
    const otherSources = old ? (old.seenBy ?? [old.connector]).filter(s=>s !== "defender") : [];
    const f: Finding = { id:old?.id ?? id("DEF",snapshot.companyId,row.deviceId,row.cve),scanId:`defender:${snapshot.companyId}`,
      companyId:snapshot.companyId,companyName,connector:"defender",seenBy:["defender"],cve:row.cve,title:row.cve,
      severity:severity(row.severity),cvss:row.cvss ?? 0,cvssV3:row.cvss ?? 0,cvssV2:0,vpr:0,epss:old?.epss ?? 0,
      asset:old?.asset ?? asset.identifier,port:"N/A",category:"Software vulnerability",
      description:`Reported by Microsoft Defender. Device: ${row.hostname || row.deviceId}. CVSS: ${row.cvss ?? "not supplied"}.`,
      remediation:row.remediation,status:old?.status === "Resolved" ? "Open" : old?.status ?? "Open",
      assignee:old?.assignee ?? null,firstSeen:old?.firstSeen ?? row.firstSeen ?? snapshot.observedAt,
      lastSeen:row.lastSeen ?? snapshot.observedAt,resolvedAt:null,exploitAvailable:row.exploitAvailable,
      kev:false,ransomware:false,assetExposure:asset.exposure,assetCriticality:asset.criticality,assetSource:asset.source,realRisk:0,riskPriority:"Info",
      defender:{ deviceId:row.deviceId,hostname:row.hostname,runId:snapshot.runId,observedAt:snapshot.observedAt,active:true,cvss:row.cvss,remediation:row.remediation } };
    if (old) {
      f.enrichments = old.enrichments; f.slaBreachAlertedAt = old.slaBreachAlertedAt;
      if (otherSources.length) {
        mergeFindingAssessment(f,old); f.lastSeen = [old.lastSeen,row.lastSeen ?? snapshot.observedAt].sort().at(-1)!; f.connector = old.connector; f.scanId = old.scanId;
        f.seenBy = [...new Set([...otherSources,"defender" as const])];
        const otherRemediation = old.defender?.otherRemediation ?? (!old.defender ? old.remediation : "");
        f.defender!.otherRemediation = otherRemediation;
        f.remediation = [...new Set([otherRemediation,row.remediation].filter(Boolean))].join("\n");
        f.title = old.title; f.description = old.description; f.port = old.port; f.category = old.category; f.cves = old.cves;
      }
    }
    Object.assign(f,score(f,asset)); changes.set(f.id,f); touched.add(f.id);
  }
  for (const old of ownFindings) {
    if (!old.defender || touched.has(old.id)) continue;
    const device = devices.get(old.defender.deviceId);
    // Disappeared/offline devices are not evidence of a successful patch.
    const heartbeat = Date.parse(device?.lastSeen ?? ""), previousObservation = Date.parse(old.defender.observedAt);
    if (!Number.isFinite(heartbeat) || !Number.isFinite(previousObservation) || heartbeat < previousObservation) continue;
    const others = (old.seenBy ?? [old.connector]).filter(s=>s !== "defender");
    const f = { ...old, defender:{ ...old.defender, active:false,runId:snapshot.runId,observedAt:snapshot.observedAt } };
    if (others.length) { f.seenBy = others; f.connector = others[0]; }
    else if (["Open","In Remediation"].includes(f.status)) { f.status = "Resolved"; f.resolvedAt = snapshot.observedAt; }
    changes.set(f.id,f);
  }
  return { findings:changes, assets:assetChanges, targets:[...deviceAssets.values()].map(a=>a.identifier) };
}
