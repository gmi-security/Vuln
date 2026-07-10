import { NextResponse } from "next/server";
import { ensureHydrated } from "@/lib/store";
import { sendTestAlert } from "@/lib/alerts";

export const dynamic = "force-dynamic";

// Session-gated (proxy.ts): send a test message to every configured alert
// channel so the settings UI can verify Slack/email config end to end.
export async function POST() {
  await ensureHydrated();
  const result = await sendTestAlert();
  return NextResponse.json(result);
}
