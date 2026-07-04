"use client";

import React, { Suspense } from "react";
import { signIn } from "next-auth/react";
import { useSearchParams } from "next/navigation";
import localFont from "next/font/local";
import { ShieldAlert } from "lucide-react";

const vibrocentric = localFont({
  src: "../fonts/Vibrocentric Rg.otf",
  display: "swap",
});

function GithubMark({ size = 18 }: { size?: number }) {
  return (
    <svg
      viewBox="0 0 16 16"
      width={size}
      height={size}
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}

function LoginInner() {
  const params = useSearchParams();
  const error = params.get("error");
  const callbackUrl = params.get("callbackUrl") || "/dashboard";

  // NextAuth sends AccessDenied when the signIn callback rejects — here that
  // means the GitHub account is not an active gmi-security org member.
  const deniedAccess = error === "AccessDenied";

  return (
    <div className="flex min-h-screen items-center justify-center bg-[radial-gradient(circle_at_50%_18%,rgba(179,14,20,0.14),transparent_38%),linear-gradient(180deg,#000_0%,#020202_100%)] px-6 text-white">
      <div className="w-full max-w-md">
        <div className="text-center">
          <div
            className={`${vibrocentric.className} text-[56px] leading-none tracking-[0.14em] text-[#b30e14]`}
          >
            VULN
          </div>
          <div className="mt-3 text-[12px] uppercase tracking-[0.36em] text-zinc-400">
            GMI Vulnerability Console
          </div>
        </div>

        <div className="mt-10 rounded-[30px] border border-[rgba(179,14,20,0.18)] bg-[#070707] p-7 shadow-[0_30px_120px_rgba(0,0,0,0.5)]">
          <h1 className="text-center text-xl font-semibold text-white">
            Sign in
          </h1>
          <p className="mt-2 text-center text-sm text-zinc-500">
            Access is restricted to members of the{" "}
            <span className="text-zinc-300">gmi-security</span> GitHub
            organization.
          </p>

          {error ? (
            <div className="mt-5 flex items-start gap-3 rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] px-4 py-3 text-sm text-[#ff4d57]">
              <ShieldAlert size={18} className="mt-0.5 shrink-0" />
              <span>
                {deniedAccess
                  ? "That GitHub account is not a member of gmi-security. Ask an org owner for an invite, then try again."
                  : "Sign-in failed. Please try again."}
              </span>
            </div>
          ) : null}

          <button
            onClick={() => signIn("github", { callbackUrl })}
            className="mt-6 flex w-full items-center justify-center gap-3 rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.16)] px-5 py-4 text-sm font-medium text-white transition hover:bg-[rgba(179,14,20,0.28)]"
          >
            <GithubMark size={18} />
            Continue with GitHub
          </button>

          <p className="mt-5 text-center text-xs text-zinc-600">
            You&apos;ll be asked to authorize read-only access to your GitHub
            profile and organization membership.
          </p>
        </div>
      </div>
    </div>
  );
}

export default function VulnLoginPage() {
  return (
    <Suspense>
      <LoginInner />
    </Suspense>
  );
}
