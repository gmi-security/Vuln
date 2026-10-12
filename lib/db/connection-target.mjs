export function safeConnectionTarget(connectionString) {
  const url = new URL(connectionString);
  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
    throw new Error("Expected a PostgreSQL connection string.");
  }
  return {
    host: url.hostname,
    port: url.port || "5432",
    database: decodeURIComponent(url.pathname.slice(1)),
  };
}

// Match the existing application's managed-Postgres transport. Private recovery
// tests use Unix sockets and have no TLS server; never disable TLS for TCP here.
export function applicationDatabaseSsl(connectionString) {
  const url = new URL(connectionString);
  if (!["postgres:", "postgresql:"].includes(url.protocol)) throw new Error("Expected a PostgreSQL connection string.");
  return (url.searchParams.get("host") ?? "").startsWith("/") ? false : { rejectUnauthorized: false };
}
