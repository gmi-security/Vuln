import { createLaunchConfiguration, superviseRuntime } from "../../scripts/start-app.mjs";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

const configuration = createLaunchConfiguration([], { ...process.env, NODE_ENV: "production",
  VULN_RUNTIME_SPLIT: "true", VULN_PLATFORM_STORE: "sql", FIXTURE_HOLD_REQUEST: "true",
  FIXTURE_IGNORE_SHUTDOWN: "true" }, "linux");
configuration.port = 0;
if (process.platform === "win32") configuration.socketPath = `\\\\.\\pipe\\vuln-parent-loss-${randomUUID()}`;
configuration.auxiliaryWorkers = [{ role: "summary", script: fileURLToPath(new URL("./runtime-auxiliary.mjs", import.meta.url)), args: [] }];
superviseRuntime(configuration, { serverScript: fileURLToPath(new URL("./runtime-child.mjs", import.meta.url)),
  onEvent(event) { process.send?.(event); },
}).then(code => process.exit(code), () => process.exit(1));
