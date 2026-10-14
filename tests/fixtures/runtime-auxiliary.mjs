if (process.env.FIXTURE_AUXILIARY_EXIT_ZERO === "true") process.exit(0);
const timer = setInterval(() => {}, 1000);
process.on("SIGTERM", () => { if (process.env.FIXTURE_IGNORE_SHUTDOWN !== "true") clearInterval(timer); });
process.on("message", message => { if (message?.type === "fixture-crash") process.exit(7); });
process.send?.({ type: "fixture-auxiliary-ready" });
