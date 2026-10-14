// Keep committed reporting reads on web; only these GETs share live job/config
// state with the writer. All API mutations use the writer independently.
const writerReadPaths = [
  "/api/elastic-dashboard/customer-sync",
  "/api/tidal/import",
  "/api/automate/import",
  "/api/crowdstrike/import",
  "/api/connectors/sync-all",
  "/api/crowdstrike/debug",
  "/api/crowdstrike/spotlight-import",
];
const writerReadTrees = [
  "/api/defender/connections",
];
const mutations = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const inTree = (path, root) => path === root || path.startsWith(`${root}/`);

export function shouldForwardToWorker(method, url) {
  let path;
  try { path = decodeURIComponent(new URL(url, "http://runtime.local").pathname).replace(/\/+$/, ""); }
  catch { return false; }
  method = method?.toUpperCase();
  if (mutations.has(method)) return inTree(path, "/api") && !inTree(path, "/api/auth");
  if (method !== "GET" && method !== "HEAD") return false;
  return writerReadPaths.includes(path) || writerReadTrees.some(root => inTree(path, root));
}
