import { NextResponse } from "next/server";
import { emailConfigured, slackConfigured } from "@/lib/alerts";

export const dynamic = "force-dynamic";

// Reachability probe for the alerting channels, shaped like the scanner
// health endpoints ({ reachable, message }) so the Connectors page can show
// a live health dot. ?channel=slack|email.
export async function GET(request: Request) {
  const channel = new URL(request.url).searchParams.get("channel");

  if (channel === "slack") {
    // A Slack incoming webhook can only be verified by posting to it, which
    // would spam the channel — so report config state only. The Settings
    // page's "Send test alert" does the real end-to-end check.
    if (!slackConfigured()) {
      return NextResponse.json({
        configured: false,
        reachable: false,
        message: "SLACK_WEBHOOK_URL not set — planned.",
      });
    }
    return NextResponse.json({
      configured: true,
      reachable: true,
      message: "Webhook configured — use Send test alert in Settings to verify delivery.",
    });
  }

  if (channel === "email") {
    if (!emailConfigured()) {
      return NextResponse.json({
        configured: false,
        reachable: false,
        message: "RESEND_API_KEY / REPORT_FROM_EMAIL not set.",
      });
    }
    // Verify the API key with a read-only call (no email is sent).
    try {
      const res = await fetch("https://api.resend.com/domains", {
        headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY!.trim()}` },
        signal: AbortSignal.timeout(8000),
        cache: "no-store",
      });
      if (res.ok) {
        return NextResponse.json({
          configured: true,
          reachable: true,
          message: `Resend API key valid — sending as ${process.env.REPORT_FROM_EMAIL!.trim()}.`,
        });
      }
      return NextResponse.json({
        configured: true,
        reachable: false,
        message:
          res.status === 401
            ? "Resend rejected the API key (HTTP 401) — check RESEND_API_KEY."
            : `Resend API returned HTTP ${res.status}.`,
      });
    } catch {
      return NextResponse.json({
        configured: true,
        reachable: false,
        message: "Could not reach the Resend API.",
      });
    }
  }

  return NextResponse.json({ error: "Unknown channel." }, { status: 400 });
}
