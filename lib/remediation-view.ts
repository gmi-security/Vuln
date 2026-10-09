export const remediationViews = ["overview", "prioritize", "tickets"] as const;
export type RemediationView = typeof remediationViews[number];

export function remediationView(value: unknown): RemediationView {
  return value === "prioritize" || value === "tickets" ? value : "overview";
}

// The selected customer is the app's existing company ID, never a source tenant
// or a customer inferred from a tile title. This helper only builds navigation;
// existing APIs remain responsible for authenticating and validating scope.
export function remediationHref(companyId: string, view: RemediationView = "overview") {
  const params = new URLSearchParams();
  if (companyId) params.set("companyId", companyId);
  if (view !== "overview") params.set("view", view);
  const query = params.toString();
  return `/remediation${query ? `?${query}` : ""}`;
}
