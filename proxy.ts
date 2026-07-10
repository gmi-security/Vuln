import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";

// Edge auth gate (Next 16 "proxy" convention). Every request that isn't a
// public asset, the login page, or an auth endpoint must carry a valid
// session token; otherwise it's redirected to /login. Org-membership
// enforcement happens at sign-in time in lib/auth.ts.
const PUBLIC_ASSET_PREFIXES = ["/_next", "/favicon.ico", "/fonts"];

function isPublicAsset(pathname: string) {
  return PUBLIC_ASSET_PREFIXES.some((path) => pathname.startsWith(path));
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (
    isPublicAsset(pathname) ||
    pathname.startsWith("/api/auth") ||
    pathname === "/api/nessus/health" ||
    pathname === "/api/spiderfoot/health" ||
    pathname === "/api/artemis/health" ||
    pathname === "/api/burp/health" ||
    pathname === "/api/nmap/health" ||
    pathname === "/api/vulners/health" ||
    pathname === "/api/crowdstrike/health" ||
    pathname === "/api/health" ||
    // Independently protected by ADMIN_TOKEN (not a session), so they must stay
    // reachable without the login redirect.
    pathname === "/api/admin/resync" ||
    pathname === "/api/admin/purge-demo" ||
    pathname === "/api/grc/assessment"
  ) {
    return NextResponse.next();
  }

  const token = await getToken({
    req: request,
    secret: process.env.NEXTAUTH_SECRET,
  });

  const isLoginPage = pathname === "/login";

  if (!token) {
    if (isLoginPage) return NextResponse.next();
    // API callers expect JSON, not the login page — a 302 to HTML makes the
    // client's res.json() blow up. Pages keep the redirect.
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Signed in but sitting on /login → send to the dashboard.
  if (isLoginPage) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
