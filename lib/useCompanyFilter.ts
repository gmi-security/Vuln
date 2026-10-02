"use client";

import { useCallback } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

// Single shared convention for "which company is this list page scoped to":
// the ?company= URL param, read and written the same way everywhere. Before
// this, four pages implemented four different (and mostly one-way) versions
// of company selection -- a dropdown's local useState that never touched the
// URL, so refreshing or sharing a link lost the selection, and every link
// into these pages except one (Findings) dropped the company context
// entirely. Deriving the selected value directly from searchParams on every
// render (instead of seeding local state once) makes the URL the actual
// source of truth, so an incoming `?company=CO-1` link always wins.
export function useCompanyFilter(): [string, (id: string) => void] {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const selected = searchParams.get("company") ?? "All";
  const setSelected = useCallback(
    (id: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (id === "All") params.delete("company");
      else params.set("company", id);
      const qs = params.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [router, pathname, searchParams],
  );
  return [selected, setSelected];
}
