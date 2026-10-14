// Exercise the real child server and supervisor without a production build or
// provider credentials. Only the Next application boundary is substituted.
import { runRuntimeServer } from "../../scripts/runtime-server.mjs";

const role = process.env.VULN_RUNTIME_ROLE;
const delay = Number(process.env.FIXTURE_PREPARE_DELAY ?? 0);
const createApp = async () => ({
  async prepare() { if (delay) await new Promise(resolve => setTimeout(resolve, delay)); },
  getRequestHandler() { return (_req, res) => {
    if (process.env.FIXTURE_HOLD_REQUEST === "true") { res.writeHead(200); res.write("holding"); }
    else res.end(role);
  }; },
  async close() {},
});
if (process.env.FIXTURE_CRASH_ROLE === role) process.on("message", message => {
  if (message?.type === "fixture-crash") process.exit(7);
});
runRuntimeServer({ createApp }).then(() => process.exit(0), error => {
  console.error(error.message); process.exit(1);
});
