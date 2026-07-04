import https from "node:https";
import http from "node:http";
import type { Severity } from "@/lib/types";

// Tenable Nessus REST adapter. Authenticated requests send the
// "X-ApiKeys: accessKey=...; secretKey=..." header per the Nessus API docs.
// Nessus commonly runs with a self-signed certificate; set
// NESSUS_TLS_INSECURE=1 to skip TLS verification for that scanner only.

export type NessusConfig = {
  url: string;
  accessKey: string;
  secretKey: string;
  insecure: boolean;
};

export function nessusConfig(): NessusConfig | null {
  const url = process.env.NESSUS_URL;
  const accessKey = process.env.NESSUS_ACCESS_KEY;
  const secretKey = process.env.NESSUS_SECRET_KEY;
  if (!url || !accessKey || !secretKey) return null;
  return {
    url: url.replace(/\/+$/, ""),
    accessKey,
    secretKey,
    insecure: process.env.NESSUS_TLS_INSECURE === "1",
  };
}

function request(
  config: NessusConfig,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const target = new URL(config.url + path);
    const payload = body ? JSON.stringify(body) : null;
    const transport = target.protocol === "http:" ? http : https;
    const req = transport.request(
      {
        method,
        hostname: target.hostname,
        port: target.port || (target.protocol === "http:" ? 80 : 443),
        path: target.pathname + target.search,
        rejectUnauthorized: !config.insecure,
        timeout: 15_000,
        headers: {
          "X-ApiKeys": `accessKey=${config.accessKey}; secretKey=${config.secretKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
          ...(payload ? { "Content-Length": Buffer.byteLength(payload) } : {}),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          let json: any = null;
          try {
            json = data ? JSON.parse(data) : null;
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("Nessus request timed out")));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function api(
  config: NessusConfig,
  method: string,
  path: string,
  body?: unknown,
): Promise<any> {
  const res = await request(config, method, path, body);
  if (res.status < 200 || res.status >= 300) {
    const detail = res.json?.error ?? `HTTP ${res.status}`;
    throw new Error(`Nessus ${method} ${path} failed: ${detail}`);
  }
  return res.json;
}

// Map console scan profiles onto Nessus editor templates by name.
const PROFILE_TEMPLATE: Record<string, string> = {
  discovery: "discovery",
  standard: "basic",
  credentialed: "basic",
  pci: "pci-dss",
  "agent-sync": "basic",
};

export async function nessusLaunchScan(
  name: string,
  targets: string[],
  profile: string,
): Promise<{ nessusScanId: number }> {
  const config = nessusConfig();
  if (!config) throw new Error("Nessus is not configured.");

  const templates = await api(config, "GET", "/editor/scan/templates");
  const wanted = PROFILE_TEMPLATE[profile] ?? "basic";
  const list: any[] = templates?.templates ?? [];
  const template =
    list.find((t) => t.name === wanted) ??
    list.find((t) => t.name === "basic") ??
    list[0];
  if (!template) throw new Error("No scan templates available on the scanner.");

  const created = await api(config, "POST", "/scans", {
    uuid: template.uuid,
    settings: {
      name,
      description: "Launched from GMI Vuln console",
      text_targets: targets.join(","),
      enabled: false,
    },
  });
  const scanId: number = created?.scan?.id;
  if (!scanId) throw new Error("Nessus did not return a scan id.");

  await api(config, "POST", `/scans/${scanId}/launch`);
  return { nessusScanId: scanId };
}

// Lightweight connectivity/activation probe for the scanner. Returns whether
// the app can reach the Nessus API and whether it's ready (activated + plugins
// compiled) vs still loading or unlicensed ("API is not available").
export async function nessusServerStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  ready: boolean;
  status: string;
  message: string;
}> {
  const config = nessusConfig();
  if (!config) {
    return {
      configured: false,
      reachable: false,
      ready: false,
      status: "not-configured",
      message: "NESSUS_URL / API keys not set",
    };
  }
  try {
    const res = await request(config, "GET", "/server/status");
    if (res.status >= 200 && res.status < 300) {
      const status = String(res.json?.status ?? "unknown");
      return {
        configured: true,
        reachable: true,
        ready: status === "ready",
        status,
        message: status === "ready" ? "Scanner ready" : `Scanner status: ${status}`,
      };
    }
    return {
      configured: true,
      reachable: true,
      ready: false,
      status: `http-${res.status}`,
      message: res.json?.error ?? `HTTP ${res.status} — likely not activated`,
    };
  } catch (err) {
    return {
      configured: true,
      reachable: false,
      ready: false,
      status: "unreachable",
      message: err instanceof Error ? err.message : "unreachable",
    };
  }
}

export type NessusFolder = {
  id: number;
  name: string;
  type: string; // "main" | "custom" | "trash"
};

// List the folders configured on the scanner. In an MSSP setup each folder
// typically represents a client, so these map onto Vuln companies.
export async function nessusListFolders(): Promise<NessusFolder[]> {
  const config = nessusConfig();
  if (!config) throw new Error("Nessus is not configured.");
  const data = await api(config, "GET", "/folders");
  const folders: any[] = data?.folders ?? [];
  return folders.map((f) => ({
    id: Number(f.id),
    name: String(f.name),
    type: String(f.type ?? "custom"),
  }));
}

export type NessusScanSummary = {
  id: number;
  name: string;
  folderId: number;
  status: string;
  lastModified: number | null;
};

// List all scans on the scanner with their folder assignment and status.
export async function nessusListScans(): Promise<NessusScanSummary[]> {
  const config = nessusConfig();
  if (!config) throw new Error("Nessus is not configured.");
  const data = await api(config, "GET", "/scans");
  const scans: any[] = data?.scans ?? [];
  return scans.map((sc) => ({
    id: Number(sc.id),
    name: String(sc.name ?? `Nessus scan ${sc.id}`),
    folderId: Number(sc.folder_id),
    status: String(sc.status ?? "completed"),
    lastModified: sc.last_modification_date ? Number(sc.last_modification_date) : null,
  }));
}

export async function nessusScanStatus(
  nessusScanId: number,
): Promise<{ status: string; progress: number }> {
  const config = nessusConfig();
  if (!config) throw new Error("Nessus is not configured.");
  const detail = await api(config, "GET", `/scans/${nessusScanId}`);
  const info = detail?.info ?? {};
  const hosts: any[] = detail?.hosts ?? [];
  let progress = 0;
  if (hosts.length) {
    const parts = hosts.map((h) => {
      const done = Number(h.scanprogresscurrent ?? 0);
      const total = Number(h.scanprogresstotal ?? 0);
      return total > 0 ? done / total : 0;
    });
    progress = Math.round(
      (parts.reduce((sum: number, p: number) => sum + p, 0) / hosts.length) * 100,
    );
  }
  const status = String(info.status ?? "running");
  if (status === "completed") progress = 100;
  return { status, progress };
}

export async function nessusScanControl(
  nessusScanId: number,
  action: "pause" | "resume" | "stop",
): Promise<void> {
  const config = nessusConfig();
  if (!config) throw new Error("Nessus is not configured.");
  await api(config, "POST", `/scans/${nessusScanId}/${action}`);
}

const NESSUS_SEVERITY: Record<number, Severity> = {
  4: "Critical",
  3: "High",
  2: "Medium",
  1: "Low",
  0: "Info",
};

export type NessusFinding = {
  cve: string;
  title: string;
  severity: Severity;
  cvss: number;
  cvssV2: number;
  cvssV3: number;
  vpr: number;
  asset: string;
  port: string;
  category: string;
  description: string;
  remediation: string;
  exploitAvailable: boolean;
};

// Pull per-host vulnerabilities, enriching the most severe plugins with
// full detail (description, solution, CVE, CVSS). Detail lookups are capped
// so importing a large scan stays fast.
export async function nessusImportFindings(
  nessusScanId: number,
  detailBudget = 40,
): Promise<NessusFinding[]> {
  const config = nessusConfig();
  if (!config) throw new Error("Nessus is not configured.");
  const detail = await api(config, "GET", `/scans/${nessusScanId}`);
  const hosts: any[] = detail?.hosts ?? [];
  const findings: NessusFinding[] = [];
  const pluginCache = new Map<number, any>();
  let detailCalls = 0;

  for (const host of hosts) {
    const hostDetail = await api(
      config,
      "GET",
      `/scans/${nessusScanId}/hosts/${host.host_id}`,
    );
    const hostname: string =
      hostDetail?.info?.["host-fqdn"] ?? hostDetail?.info?.["host-ip"] ?? host.hostname;
    const vulns: any[] = (hostDetail?.vulnerabilities ?? []).sort(
      (a: any, b: any) => (b.severity ?? 0) - (a.severity ?? 0),
    );

    for (const vuln of vulns) {
      const severity = NESSUS_SEVERITY[Number(vuln.severity ?? 0)] ?? "Info";
      let plugin = pluginCache.get(vuln.plugin_id);
      if (!plugin && detailCalls < detailBudget && Number(vuln.severity ?? 0) >= 1) {
        try {
          plugin = await api(
            config,
            "GET",
            `/scans/${nessusScanId}/hosts/${host.host_id}/plugins/${vuln.plugin_id}`,
          );
          pluginCache.set(vuln.plugin_id, plugin);
          detailCalls += 1;
        } catch {
          plugin = null;
        }
      }

      const attributes: any[] = plugin?.info?.plugindescription?.pluginattributes
        ? [plugin.info.plugindescription.pluginattributes]
        : [];
      const attrs = attributes[0] ?? {};
      const cve: string = Array.isArray(attrs?.cve) ? attrs.cve[0] : attrs?.cve ?? "";
      const outputs: any[] = plugin?.outputs ?? [];
      const port =
        outputs[0]?.ports && Object.keys(outputs[0].ports)[0]
          ? Object.keys(outputs[0].ports)[0].split(" ")[0]
          : "N/A";

      const cvssV3 = Number(attrs?.risk_information?.cvss3_base_score ?? 0);
      const cvssV2 = Number(attrs?.risk_information?.cvss_base_score ?? 0);
      const vpr = Number(
        attrs?.risk_information?.vpr_score ?? attrs?.vpr_score ?? vuln?.vpr_score ?? 0,
      );
      findings.push({
        cve: cve || `PLUGIN-${vuln.plugin_id}`,
        title: String(vuln.plugin_name ?? `Nessus plugin ${vuln.plugin_id}`),
        severity,
        cvss: cvssV3 || cvssV2,
        cvssV2,
        cvssV3,
        vpr,
        asset: hostname,
        port,
        category: String(vuln.plugin_family ?? "Nessus"),
        description: String(attrs?.description ?? "Imported from Nessus scan results."),
        remediation: String(attrs?.solution ?? "See the Nessus plugin output for remediation guidance."),
        exploitAvailable:
          String(attrs?.vuln_information?.exploit_available ?? "false") === "true",
      });
    }
  }
  return findings;
}
