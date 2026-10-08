// Decrypts the app's own saved ConnectWise connection (patch_connectwise_connection.secret)
// the exact same way lib/connectwise-client.ts's openCWConnection does, and prints it as
// ready-to-eval CW_* export lines -- so you don't have to hunt down or regenerate API Member
// keys that are already saved and already in active use by the app.
//
//   eval "$(node --env-file=.env.local scripts/print-saved-connectwise-connection.mjs)"
//
// Required env: DATABASE_URL (or ELASTIC_VULN_DATABASE_URL if this instance uses a separate
// dashboard DB), NEXTAUTH_SECRET (same secret the app itself uses to decrypt this connection).

import pg from "pg";
import { createDecipheriv, hkdfSync } from "node:crypto";

const secret = process.env.NEXTAUTH_SECRET;
if (!secret || secret.length < 32) throw new Error("NEXTAUTH_SECRET is required (same one the app uses).");
const dbUrl = process.env.ELASTIC_VULN_DATABASE_URL || process.env.DATABASE_URL;
if (!dbUrl) throw new Error("DATABASE_URL is required.");

function key() {
  return Buffer.from(hkdfSync("sha256", secret, "gmi-vuln", "connectwise-connection-v1", 32));
}
function openCWConnection(value) {
  const [version, iv, tag, data] = value.split(".");
  if (version !== "v1") throw new Error("Unexpected connection format.");
  const cipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64"));
  cipher.setAuthTag(Buffer.from(tag, "base64"));
  return JSON.parse(Buffer.concat([cipher.update(Buffer.from(data, "base64")), cipher.final()]).toString("utf8"));
}

const pool = new pg.Pool({ connectionString: dbUrl, ssl: { rejectUnauthorized: false }, max: 1, connectionTimeoutMillis: 8000 });
try {
  const { rows } = await pool.query("SELECT secret FROM patch_connectwise_connection WHERE id=1");
  if (!rows.length) throw new Error("No saved ConnectWise connection found (patch_connectwise_connection is empty).");
  const conn = openCWConnection(rows[0].secret);
  console.log(`export CW_ENDPOINT=${conn.endpoint}`);
  console.log(`export CW_COMPANY_ID=${conn.companyId}`);
  console.log(`export CW_CLIENT_ID=${conn.clientId}`);
  console.log(`export CW_PUBLIC_KEY=${conn.publicKey}`);
  console.log(`export CW_PRIVATE_KEY=${conn.privateKey}`);
} finally {
  await pool.end();
}
