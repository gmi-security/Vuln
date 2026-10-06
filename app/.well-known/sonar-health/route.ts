export function GET() {
  return Response.json({
    service: "Vuln",
    targets: [
      { id: "crowdstrike", name: "CrowdStrike Connector", provider: "CrowdStrike", checkType: "VULN_CONNECTOR", healthPath: "/api/crowdstrike/health", authProfile: "NONE" },
      { id: "nessus", name: "Nessus Connector", provider: "Nessus", checkType: "VULN_CONNECTOR", healthPath: "/api/nessus/health", authProfile: "NONE" },
      { id: "spiderfoot", name: "SpiderFoot Connector", provider: "SpiderFoot", checkType: "VULN_CONNECTOR", healthPath: "/api/spiderfoot/health", authProfile: "NONE" },
      { id: "zap", name: "ZAP Connector", provider: "ZAP", checkType: "VULN_CONNECTOR", healthPath: "/api/zap/health", authProfile: "NONE" },
      { id: "artemis", name: "Artemis Connector", provider: "Artemis", checkType: "VULN_CONNECTOR", healthPath: "/api/artemis/health", authProfile: "NONE" },
      { id: "nmap", name: "Nmap Connector", provider: "Nmap", checkType: "VULN_CONNECTOR", healthPath: "/api/nmap/health", authProfile: "NONE" },
      { id: "burp", name: "Burp Connector", provider: "Burp", checkType: "VULN_CONNECTOR", healthPath: "/api/burp/health", authProfile: "NONE" },
      { id: "n8n", name: "n8n Connector", provider: "n8n", checkType: "VULN_CONNECTOR", healthPath: "/api/n8n/health", authProfile: "NONE" },
      { id: "vulners-bridge", name: "Vulners Bridge Connector", provider: "Vulners Bridge", checkType: "VULN_CONNECTOR", healthPath: "/api/vulners-bridge-health", authProfile: "NONE" },
    ],
  });
}
