import type { AssetCriticality, AssetExposure } from "@/lib/types";

// Microsoft Intune (Endpoint Manager) asset adapter.
//
// Intune holds the managed-device inventory for a tenant — device name, OS,
// primary user, compliance, ownership. We pull it via the Microsoft Graph API
// (app-only / client credentials) and use it as environmental context for
// endpoints. Devices belong to the tenant, i.e. our own organization.
//
// Configure with an Entra app registration granted
// DeviceManagementManagedDevices.Read.All (application permission):
//   INTUNE_TENANT_ID       directory (tenant) id
//   INTUNE_CLIENT_ID       app (client) id
//   INTUNE_CLIENT_SECRET   client secret

export type IntuneConfig = {
  tenantId: string;
  clientId: string;
  clientSecret: string;
};

export function intuneConfig(): IntuneConfig | null {
  const tenantId = process.env.INTUNE_TENANT_ID;
  const clientId = process.env.INTUNE_CLIENT_ID;
  const clientSecret = process.env.INTUNE_CLIENT_SECRET;
  if (!tenantId || !clientId || !clientSecret) return null;
  return { tenantId, clientId, clientSecret };
}

export type IntuneAsset = {
  externalId: string;
  hostname: string;
  ipAddresses: string[];
  os: string;
  owner: string;
  tags: string[];
  criticality: AssetCriticality;
  exposure: AssetExposure;
};

async function graphToken(config: IntuneConfig): Promise<string> {
  const res = await fetch(
    `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        scope: "https://graph.microsoft.com/.default",
        grant_type: "client_credentials",
      }),
      cache: "no-store",
    },
  );
  if (!res.ok) {
    throw new Error(
      `Intune auth failed: ${res.status} ${await res.text().catch(() => res.statusText)}`,
    );
  }
  const data = (await res.json()) as { access_token?: string };
  if (!data.access_token) throw new Error("Intune auth returned no token.");
  return data.access_token;
}

// Managed endpoints are internal by nature. Criticality leans Normal, with
// server OSes treated as High and personal devices as Low.
function classifyDevice(raw: any): {
  exposure: AssetExposure;
  criticality: AssetCriticality;
} {
  const os = String(raw?.operatingSystem ?? "").toLowerCase();
  const ownerType = String(raw?.managedDeviceOwnerType ?? "").toLowerCase();
  let criticality: AssetCriticality = "Normal";
  if (/server/.test(os)) criticality = "High";
  else if (ownerType === "personal") criticality = "Low";
  return { exposure: "Internal", criticality };
}

function normalizeIntuneDevice(raw: any): IntuneAsset {
  const { exposure, criticality } = classifyDevice(raw);
  const os = [raw?.operatingSystem, raw?.osVersion].filter(Boolean).join(" ");
  const tags = [
    raw?.complianceState ? `compliance:${raw.complianceState}` : "",
    raw?.managedDeviceOwnerType ? `owner:${raw.managedDeviceOwnerType}` : "",
  ].filter(Boolean);
  return {
    externalId: String(raw?.id ?? ""),
    hostname: String(raw?.deviceName ?? raw?.managedDeviceName ?? ""),
    ipAddresses: [],
    os,
    owner: String(raw?.userPrincipalName ?? raw?.userDisplayName ?? ""),
    tags,
    criticality,
    exposure,
  };
}

// Pull managed devices from Graph, following @odata.nextLink pagination.
export async function intuneListAssets(): Promise<IntuneAsset[]> {
  const config = intuneConfig();
  if (!config) throw new Error("Intune is not configured.");
  const token = await graphToken(config);

  const assets: IntuneAsset[] = [];
  let url: string | null =
    "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=200&$select=id,deviceName,managedDeviceName,operatingSystem,osVersion,userPrincipalName,userDisplayName,complianceState,managedDeviceOwnerType,model,serialNumber";
  let guard = 0;
  while (url && guard < 100) {
    guard += 1;
    const res: Response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      cache: "no-store",
    });
    if (!res.ok) {
      throw new Error(
        `Intune Graph ${res.status}: ${await res.text().catch(() => res.statusText)}`,
      );
    }
    const data: any = await res.json();
    for (const d of data?.value ?? []) {
      const asset = normalizeIntuneDevice(d);
      if (asset.hostname) assets.push(asset);
    }
    url = data?.["@odata.nextLink"] ?? null;
  }
  return assets;
}
