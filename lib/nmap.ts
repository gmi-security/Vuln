import type { OpenPort, Severity } from "@/lib/types";

// Nmap adapter — network discovery & service enumeration (class: discovery).
//
// Nmap is deliberately NOT wired as a fourth vulnerability scanner (Nessus
// already owns that lens). Its job here is ground truth about the network:
// which ports are actually open and what's listening. Those facts are attached
// to inventory assets — sharpening the attack-path/beachhead model, which today
// infers reachability from hostnames — and Nmap emits findings only for the
// narrow, unambiguous set of genuinely risky exposed services (RDP/SMB/Telnet/
// databases reachable), never the noise a full scanner would.
//
// Two ingestion paths, mirroring the other connectors:
//   1. A scan-runner service that executes nmap and returns -oX XML
//      (NMAP_RUNNER_URL + NMAP_RUNNER_TOKEN).
//   2. An nmap -oX XML export uploaded from the UI (works with no runner).
//
// GOVERNANCE: active Nmap scanning is a probe, not a passive telemetry pull.
// Only scan customer ranges you are contracted to. The runner is expected to
// enforce per-customer scope; the upload path trusts the operator's export.

export type NmapConfig = { url: string; token: string };

export function nmapConfig(): NmapConfig | null {
  const url = process.env.NMAP_RUNNER_URL;
  const token = process.env.NMAP_RUNNER_TOKEN;
  if (!url || !token) return null;
  return { url: url.replace(/\/+$/, ""), token };
}

export type NmapHost = {
  host: string; // hostname when resolved, else the IP
  ip: string;
  os: string;
  ports: OpenPort[];
};

// Risky services that warrant a finding when found listening. Keyed by the
// well-known port; service-name keywords catch non-standard ports. Each entry
// is a management/lateral-movement/data service that should not be broadly
// reachable — the kind of exposure Nmap is uniquely good at surfacing.
type RiskDef = { label: string; severity: Severity; why: string };
const RISKY_PORTS: Record<number, RiskDef> = {
  21: { label: "FTP", severity: "Medium", why: "Cleartext file transfer." },
  23: { label: "Telnet", severity: "High", why: "Cleartext remote administration." },
  135: { label: "MSRPC", severity: "Medium", why: "Windows RPC endpoint mapper exposed." },
  139: { label: "NetBIOS", severity: "High", why: "Legacy SMB/NetBIOS exposed." },
  445: { label: "SMB", severity: "High", why: "SMB reachable — a primary ransomware/lateral-movement vector." },
  512: { label: "rexec", severity: "High", why: "Cleartext remote execution." },
  513: { label: "rlogin", severity: "High", why: "Cleartext remote login." },
  514: { label: "rsh", severity: "High", why: "Cleartext remote shell." },
  1433: { label: "MSSQL", severity: "High", why: "Database service directly reachable." },
  1521: { label: "Oracle DB", severity: "High", why: "Database service directly reachable." },
  3306: { label: "MySQL", severity: "High", why: "Database service directly reachable." },
  3389: { label: "RDP", severity: "High", why: "RDP reachable — brute-force and exploit vector." },
  4444: { label: "Metasploit/Backdoor", severity: "High", why: "Common backdoor/C2 port listening." },
  5432: { label: "PostgreSQL", severity: "High", why: "Database service directly reachable." },
  5900: { label: "VNC", severity: "High", why: "Remote desktop control reachable." },
  5901: { label: "VNC", severity: "High", why: "Remote desktop control reachable." },
  6379: { label: "Redis", severity: "High", why: "Unauthenticated-by-default datastore reachable." },
  9200: { label: "Elasticsearch", severity: "High", why: "Search datastore reachable." },
  11211: { label: "Memcached", severity: "Medium", why: "Amplification-prone cache reachable." },
  27017: { label: "MongoDB", severity: "High", why: "Document datastore reachable." },
  161: { label: "SNMP", severity: "Medium", why: "SNMP exposed — device enumeration risk." },
  389: { label: "LDAP", severity: "Medium", why: "Directory service exposed." },
};

const SERVICE_KEYWORDS: { re: RegExp; def: RiskDef }[] = [
  { re: /telnet/i, def: RISKY_PORTS[23] },
  { re: /\bsmb\b|microsoft-ds|netbios/i, def: RISKY_PORTS[445] },
  { re: /ms-wbt|rdp|term(inal)?serv/i, def: RISKY_PORTS[3389] },
  { re: /\bvnc\b/i, def: RISKY_PORTS[5900] },
  { re: /\bftp\b/i, def: RISKY_PORTS[21] },
  { re: /mysql/i, def: RISKY_PORTS[3306] },
  { re: /postgres/i, def: RISKY_PORTS[5432] },
  { re: /ms-?sql/i, def: RISKY_PORTS[1433] },
  { re: /mongod/i, def: RISKY_PORTS[27017] },
  { re: /\bredis\b/i, def: RISKY_PORTS[6379] },
  { re: /elastic/i, def: RISKY_PORTS[9200] },
  { re: /\bsnmp\b/i, def: RISKY_PORTS[161] },
];

// The risk verdict for an open port, or null when it's benign/expected.
export function portRisk(p: OpenPort): RiskDef | null {
  if (RISKY_PORTS[p.port]) return RISKY_PORTS[p.port];
  const svc = `${p.service} ${p.product}`;
  for (const { re, def } of SERVICE_KEYWORDS) {
    if (re.test(svc)) return def;
  }
  return null;
}

function severityCvss(sev: Severity): number {
  return { Critical: 9.5, High: 8.0, Medium: 5.5, Low: 3.0, Info: 0 }[sev];
}

// --- Reachability probe -----------------------------------------------------
export async function nmapStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  status: string;
  message: string;
}> {
  const config = nmapConfig();
  if (!config) {
    return {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message: "Set NMAP_RUNNER_URL and NMAP_RUNNER_TOKEN, or upload an nmap -oX XML export.",
    };
  }
  try {
    const res = await fetch(`${config.url}/health`, {
      headers: { Authorization: `Bearer ${config.token}` },
      cache: "no-store",
    });
    return {
      configured: true,
      reachable: res.ok,
      status: res.ok ? "Connected" : `HTTP ${res.status}`,
      message: res.ok ? "Scan runner reachable." : await res.text().catch(() => res.statusText),
    };
  } catch (err) {
    return {
      configured: true,
      reachable: false,
      status: "Unreachable",
      message: err instanceof Error ? err.message : "Connection failed.",
    };
  }
}

// --- Scan-runner pull -------------------------------------------------------
// Expects a small runner service that executes nmap against an authorized
// scope and returns the -oX XML. Schema is intentionally simple; adjust the
// endpoint to your runner when you stand one up.
export async function nmapListHosts(): Promise<NmapHost[]> {
  const config = nmapConfig();
  if (!config) throw new Error("Nmap runner is not configured. Set NMAP_RUNNER_URL and NMAP_RUNNER_TOKEN.");
  const res = await fetch(`${config.url}/latest.xml`, {
    headers: { Authorization: `Bearer ${config.token}` },
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Nmap runner ${res.status}: ${await res.text().catch(() => res.statusText)}`);
  }
  return parseNmapXml(await res.text());
}

// --- nmap -oX XML parse -----------------------------------------------------
// Lightweight regex parse of Nmap's XML output. Each <host> carries
// <address>, optional <hostname>, an optional <os>, and <ports><port> entries
// with <state> and <service>. We keep only open ports.
function attr(tag: string, name: string): string {
  const m = tag.match(new RegExp(`\\b${name}="([^"]*)"`, "i"));
  return m ? m[1] : "";
}

export function parseNmapXml(text: string): NmapHost[] {
  const out: NmapHost[] = [];
  const hostBlocks = text.match(/<host\b[\s\S]*?<\/host>/gi) ?? [];
  for (const block of hostBlocks) {
    // Prefer the IPv4 address; fall back to any address.
    const addrs = block.match(/<address\b[^>]*\/?>/gi) ?? [];
    let ip = "";
    for (const a of addrs) {
      if (/addrtype="ipv4"/i.test(a)) {
        ip = attr(a, "addr");
        break;
      }
      if (!ip) ip = attr(a, "addr");
    }
    const hostnameTag = block.match(/<hostname\b[^>]*\/?>/i);
    const hostname = hostnameTag ? attr(hostnameTag[0], "name") : "";

    const osMatch = block.match(/<osmatch\b[^>]*\/?>/i);
    const os = osMatch ? attr(osMatch[0], "name") : "";

    const ports: OpenPort[] = [];
    const portBlocks = block.match(/<port\b[\s\S]*?<\/port>/gi) ?? [];
    for (const pb of portBlocks) {
      const stateTag = pb.match(/<state\b[^>]*\/?>/i);
      const state = stateTag ? attr(stateTag[0], "state") : "";
      if (state.toLowerCase() !== "open") continue;
      const portId = Number(attr(pb.match(/<port\b[^>]*>/i)?.[0] ?? "", "portid"));
      const protocol = attr(pb.match(/<port\b[^>]*>/i)?.[0] ?? "", "protocol") || "tcp";
      const svcTag = pb.match(/<service\b[^>]*\/?>/i);
      const service = svcTag ? attr(svcTag[0], "name") : "";
      const product = svcTag ? attr(svcTag[0], "product") : "";
      const version = svcTag ? attr(svcTag[0], "version") : "";
      if (!portId) continue;
      ports.push({ port: portId, protocol, service, product, version });
    }
    if (!ip && !hostname) continue;
    out.push({ host: hostname || ip, ip, os, ports });
  }
  return out;
}

// Turn a host's open ports into the narrow set of exposed-service findings.
export type NmapServiceFinding = {
  cve: string; // synthetic NMAP-<label> (no real CVE)
  title: string;
  severity: Severity;
  cvss: number;
  asset: string;
  port: string;
  category: string;
  description: string;
  remediation: string;
};

export function nmapServiceFindings(host: NmapHost): NmapServiceFinding[] {
  const out: NmapServiceFinding[] = [];
  for (const p of host.ports) {
    const risk = portRisk(p);
    if (!risk) continue;
    const banner = [p.product, p.version].filter(Boolean).join(" ").trim();
    out.push({
      cve: `NMAP-${risk.label.replace(/[^A-Za-z0-9]+/g, "-").toUpperCase()}`,
      title: `Exposed ${risk.label} service (${p.port}/${p.protocol})`,
      severity: risk.severity,
      cvss: severityCvss(risk.severity),
      asset: host.host,
      port: `${p.port}/${p.protocol}`,
      category: "Exposed Service",
      description: `${risk.why}${banner ? ` Detected: ${banner}.` : ""} Observed open by Nmap discovery.`,
      remediation:
        "Restrict access to this service with a firewall/ACL, place it behind a VPN, or disable it if unused.",
    });
  }
  return out;
}
