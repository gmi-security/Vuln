import { isIP } from "node:net";

type Target = { family: number; low: bigint; high: bigint } | { hostname: string };
function address(value: string): { family: number; value: bigint } | null {
  const family = isIP(value);
  if (!family || value.includes("%")) return null;
  if (family === 4) return { family, value: value.split(".").reduce((n, part) => (n << BigInt(8)) + BigInt(part), BigInt(0)) };
  let text = value;
  if (text.includes(".")) {
    const colon = text.lastIndexOf(":");
    const v4 = address(text.slice(colon + 1))!;
    text = text.slice(0, colon + 1) + (v4.value >> BigInt(16)).toString(16) + ":" + (v4.value & BigInt(65535)).toString(16);
  }
  const sides = text.split("::"), left = sides[0] ? sides[0].split(":") : [], right = sides[1] ? sides[1].split(":") : [];
  const parts = sides.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
  return { family, value: parts.reduce((n, part) => (n << BigInt(16)) + BigInt("0x" + part), BigInt(0)) };
}
function target(value: string): Target {
  if (typeof value !== "string" || value !== value.trim() || !value || value.length > 253) throw new Error("Invalid scanner target.");
  const split = value.toLowerCase().split("/"), ip = address(split[0]);
  if (ip) {
    const bits = ip.family === 4 ? 32 : 128;
    if (split.length > 2 || (split.length === 2 && !/^(0|[1-9][0-9]*)$/.test(split[1]))) throw new Error("Invalid scanner network.");
    const prefix = split.length === 2 ? Number(split[1]) : bits;
    if (prefix > bits) throw new Error("Invalid scanner network.");
    const hostBits = BigInt(bits - prefix), low = (ip.value >> hostBits) << hostBits;
    return { family: ip.family, low, high: low + (BigInt(1) << hostBits) - BigInt(1) };
  }
  const hostname = value.toLowerCase().replace(/\.$/, "");
  if (/^[0-9.-]+$/.test(hostname) || !hostname.split(".").every(p => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(p)))
    throw new Error("Use exact scanner hostnames, IP addresses or CIDR networks.");
  return { hostname };
}
export function scannerTargetMatcher(approved: readonly string[]) {
  if (!approved.length || approved.length > 100) throw new Error("Scanner routing requires approved targets.");
  const scopes = approved.map(target);
  return (value: string): boolean => {
    let requested: Target;
    try { requested = target(value); } catch { return false; }
    return scopes.some(scope => "hostname" in scope ? "hostname" in requested && scope.hostname === requested.hostname :
      !("hostname" in requested) && scope.family === requested.family && scope.low <= requested.low && scope.high >= requested.high);
  };
}
// Host aliases are trusted only within an already verified scanner folder. No DNS lookups.
export function assertScannerResultScope(approved: readonly string[], result: {
  scannedHosts: { hostname: string; assetAliases: string[] }[];
  findings: { asset: string; assetAliases: string[] }[];
}) {
  const matches = scannerTargetMatcher(approved);
  const hosts = result.scannedHosts.map(host => {
    const names = [host.hostname, ...host.assetAliases];
    if (!host.hostname || names.some(n => typeof n !== "string" || !n.trim()) || !names.some(matches))
      throw new Error("Scanner returned a host outside the approved customer targets.");
    return new Set(names);
  });
  for (const finding of result.findings) {
    if (!hosts.some(names => names.has(finding.asset) && finding.assetAliases.every(a => names.has(a))))
      throw new Error("Scanner finding does not belong to a verified scanned host.");
  }
}
