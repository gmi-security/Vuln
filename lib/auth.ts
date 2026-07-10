import type { NextAuthOptions } from "next-auth";
import GitHubProvider from "next-auth/providers/github";

// Login is GitHub OAuth restricted to members of a GitHub organization
// (gmi-security by default). Only users whose org membership is "active"
// are allowed to sign in.
const ALLOWED_ORG = process.env.GMI_ALLOWED_ORG || "gmi-security";

// Membership is re-verified on session activity so that removal from the org
// revokes console access within this window, instead of the JWT staying valid
// for its full 30-day lifetime.
const MEMBERSHIP_RECHECK_MS = 15 * 60 * 1000;
// After a transient failure (network error / 5xx / timeout) retry after this
// short interval rather than on every single request.
const MEMBERSHIP_RETRY_MS = 60 * 1000;
const MEMBERSHIP_FETCH_TIMEOUT_MS = 5000;

type MembershipResult =
  // GitHub answered; member/role reflect current org state.
  | { status: "ok"; member: boolean; role: string | null }
  // Definitive rejection: revoked/invalid token (401), forbidden (403), or
  // not a member of the org (404).
  | { status: "denied" }
  // Transient failure: network error, 5xx, or timeout. Callers should keep
  // the previous membership state (fail open) and retry later.
  | { status: "error" };

async function orgMembership(accessToken: string): Promise<MembershipResult> {
  try {
    const res = await fetch(
      `https://api.github.com/user/memberships/orgs/${ALLOWED_ORG}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        signal: AbortSignal.timeout(MEMBERSHIP_FETCH_TIMEOUT_MS),
      },
    );
    if (res.ok) {
      const data = (await res.json()) as { state?: string; role?: string };
      return {
        status: "ok",
        member: data.state === "active",
        role: data.role ?? null,
      };
    }
    if (res.status === 401 || res.status === 403 || res.status === 404) {
      return { status: "denied" };
    }
    return { status: "error" };
  } catch {
    return { status: "error" };
  }
}

export const authOptions: NextAuthOptions = {
  providers: [
    GitHubProvider({
      clientId: process.env.GITHUB_CLIENT_ID ?? "",
      clientSecret: process.env.GITHUB_CLIENT_SECRET ?? "",
      // read:org is required to check organization membership.
      authorization: { params: { scope: "read:user user:email read:org" } },
    }),
  ],
  session: { strategy: "jwt" },
  pages: { signIn: "/login" },
  callbacks: {
    // Gate sign-in on active membership of the allowed org.
    async signIn({ account }) {
      if (!account?.access_token) return false;
      const result = await orgMembership(account.access_token);
      return result.status === "ok" && result.member;
    },
    async jwt({ token, account, profile }) {
      if (account?.access_token) {
        const gh = profile as
          | { login?: string; avatar_url?: string }
          | undefined;
        token.login = gh?.login;
        token.avatar = gh?.avatar_url;
        // Keep the GitHub access token so membership can be re-verified for
        // the lifetime of the session, not just at sign-in.
        token.accessToken = account.access_token;
        const result = await orgMembership(account.access_token);
        const role = result.status === "ok" ? result.role : null;
        // GitHub org role is "admin" or "member".
        token.orgRole = role === "admin" ? "ADMIN" : "MEMBER";
        // signIn just confirmed active membership, so only a definitive
        // rejection here flips this off.
        token.orgMember =
          result.status === "ok" ? result.member : result.status !== "denied";
        token.membershipCheckedAt = Date.now();
      } else if (typeof token.accessToken === "string") {
        const checkedAt =
          typeof token.membershipCheckedAt === "number"
            ? token.membershipCheckedAt
            : 0;
        if (Date.now() - checkedAt > MEMBERSHIP_RECHECK_MS) {
          const result = await orgMembership(token.accessToken);
          if (result.status === "ok") {
            token.orgMember = result.member;
            token.orgRole = result.role === "admin" ? "ADMIN" : "MEMBER";
            token.membershipCheckedAt = Date.now();
          } else if (result.status === "denied") {
            // Removed from the org, or the OAuth grant was revoked — either
            // way the console session is over. proxy.ts enforces this.
            token.orgMember = false;
            token.membershipCheckedAt = Date.now();
          } else {
            // Transient failure: keep the previous membership state (a GitHub
            // outage must not lock the whole team out) and back-date the
            // checkpoint so the next retry happens after MEMBERSHIP_RETRY_MS
            // instead of the full re-check interval.
            token.membershipCheckedAt =
              Date.now() - MEMBERSHIP_RECHECK_MS + MEMBERSHIP_RETRY_MS;
          }
        }
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        const user = session.user as typeof session.user & {
          login?: string;
          avatar?: string;
          role?: string;
        };
        user.login = token.login as string | undefined;
        user.avatar = token.avatar as string | undefined;
        user.role = token.orgRole as string | undefined;
      }
      return session;
    },
  },
};
