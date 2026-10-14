export type NavigationCapabilities = { enabled: boolean; remediationEnabled: boolean };

export async function readNavigationCapabilities(response: Response): Promise<NavigationCapabilities> {
  if (!response.ok || response.redirected) throw new Error("Navigation unavailable");
  const data: unknown = await response.json();
  if (!data || typeof data !== "object" || !("enabled" in data) || typeof data.enabled !== "boolean"
    || ("remediationEnabled" in data && typeof data.remediationEnabled !== "boolean")) {
    throw new Error("Navigation unavailable");
  }
  return { enabled: data.enabled, remediationEnabled: data.enabled && "remediationEnabled" in data && data.remediationEnabled === true };
}
