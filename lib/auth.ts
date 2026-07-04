import type { NextAuthOptions } from "next-auth";
import GitHubProvider from "next-auth/providers/github";

// Login is GitHub OAuth restricted to members of a GitHub organization
// (gmi-security by default). Only users whose org membership is "active"
// are allowed to sign in.
const ALLOWED_ORG = process.env.GMI_ALLOWED_ORG || "gmi-security";

async function orgMembership(
  accessToken: string,
): Promise<{ member: boolean; role: string | null }> {
  try {
    const res = await fetch(
      `https://api.github.com/user/memberships/orgs/${ALLOWED_ORG}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      },
    );
    if (!res.ok) return { member: false, role: null };
    const data = (await res.json()) as { state?: string; role?: string };
    return {
      member: data.state === "active",
      role: data.role ?? null,
    };
  } catch {
    return { member: false, role: null };
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
      const { member } = await orgMembership(account.access_token);
      return member;
    },
    async jwt({ token, account, profile }) {
      if (account?.access_token) {
        const gh = profile as
          | { login?: string; avatar_url?: string }
          | undefined;
        token.login = gh?.login;
        token.avatar = gh?.avatar_url;
        const { role } = await orgMembership(account.access_token);
        // GitHub org role is "admin" or "member".
        token.orgRole = role === "admin" ? "ADMIN" : "MEMBER";
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
