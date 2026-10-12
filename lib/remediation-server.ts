// Read on the server at request time. Off until the release is reviewed.
// This flag controls navigation/UI only, never storage authority or workers.
export function remediationUiEnabled() {
  return process.env.VULN_REMEDIATION_UI === "true";
}
