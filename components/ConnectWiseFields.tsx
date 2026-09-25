"use client";
import { useEffect, useId, useRef, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { CWDefaults, CWOption } from "@/lib/connectwise-client";
import { inputClass, selectClass } from "@/components/ui";
import styles from "./QueryDashboard.module.css";

export type CWSettings = { configured: boolean; endpoint?: string; companyId?: string; clientId?: string; revision?: number; defaults: CWDefaults; error?: string };
type Lookup = { options: CWOption[]; more: boolean; page: number; revision: number };
export function ConnectWiseSelect({ label, kind, value, onChange, boardId, revision, optional = false, disabled = false }: {
  label: string; kind: string; value?: number; onChange: (id: number | undefined) => void; boardId?: number; revision?: number; optional?: boolean; disabled?: boolean;
}) {
  const id = useId();
  const generation = useRef(0);
  const selected = useRef(value); selected.current = value;
  const [options, setOptions] = useState<CWOption[]>([]), [page, setPage] = useState(1), [more, setMore] = useState(false);
  const [search, setSearch] = useState(""), [applied, setApplied] = useState(""), [busy, setBusy] = useState(false), [error, setError] = useState("");
  useEffect(() => {
    let live = true; generation.current++;
    setOptions([]); setMore(false); setPage(1); setError("");
    if (["statuses", "teams"].includes(kind) && !boardId) return () => { live = false; };
    setBusy(true);
    const params = new URLSearchParams({ kind, page: "1", ...(boardId ? { boardId: String(boardId) } : {}), ...(applied ? { search: applied } : {}), ...(selected.current ? { selectedId: String(selected.current) } : {}) });
    dashboardRequest<Lookup>(`connectwise/options?${params}`).then(data => {
      if (!live) return;
      if (revision && data.revision !== revision) throw new Error("Connection changed. Reload ConnectWise settings.");
      setOptions(data.options); setMore(data.more);
    }).catch(e => { if (live) setError(e.message); }).finally(() => { if (live) setBusy(false); });
    return () => { live = false; generation.current++; };
  }, [kind, boardId, revision, applied]);
  async function nextPage() {
    const token = generation.current;
    setBusy(true); setError("");
    try {
      const params = new URLSearchParams({ kind, page: String(page + 1), ...(boardId ? { boardId: String(boardId) } : {}), ...(applied ? { search: applied } : {}) });
      const data = await dashboardRequest<Lookup>(`connectwise/options?${params}`);
      if (token !== generation.current) return;
      if (revision && data.revision !== revision) throw new Error("Connection changed. Reload ConnectWise settings.");
      setOptions(old => [...new Map([...old, ...data.options].map(option => [option.id, option])).values()]); setPage(data.page); setMore(data.more);
    } catch (e) { if (token === generation.current) setError(e instanceof Error ? e.message : "Could not load more options."); } finally { if (token === generation.current) setBusy(false); }
  }
  return <div>
    <label htmlFor={id} className="block text-sm text-zinc-200">{label}</label>
    {kind === "companies" && <div className="mt-2 flex flex-wrap gap-2">
      <input className={`${inputClass} min-w-0 flex-1`} aria-label="Search ConnectWise companies" value={search} maxLength={100} onChange={e => setSearch(e.target.value)} placeholder="Search company name" />
      <button type="button" className={styles.button} disabled={busy || disabled} onClick={() => setApplied(search.trim())}>Search</button>
    </div>}
    <select id={id} className={`${selectClass} mt-2 block w-full`} required={!optional} disabled={disabled || busy || (["statuses", "teams"].includes(kind) && !boardId)} value={value ?? ""}
      onChange={e => onChange(e.target.value ? Number(e.target.value) : undefined)}>
      <option value="">{busy ? "Loading from ConnectWise…" : optional ? "Use board default" : `Choose ${label.toLowerCase()}`}</option>
      {value && !options.some(option => option.id === value) && <option value={value} disabled>{busy ? "Loading saved selection…" : "Selection unavailable — choose an active option"}</option>}
      {options.map(option => <option value={option.id} key={option.id}>{option.name}{option.identifier ? ` (${option.identifier})` : ""}</option>)}
    </select>
    {more && <button type="button" className={`${styles.button} mt-2`} disabled={busy || disabled} onClick={nextPage}>Load more {kind}</button>}
    {!busy && !error && options.length === 0 && <p className={styles.resultNote}>{["statuses", "teams"].includes(kind) && !boardId ? "Choose a board first." : "No matching options returned by ConnectWise."}</p>}
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
  </div>;
}
export function ConnectWiseRouting({ value, onChange, revision, disabled = false }: {
  value: CWDefaults; onChange: (value: CWDefaults) => void; revision?: number; disabled?: boolean;
}) {
  return <div className="grid gap-4 sm:grid-cols-2">
    <ConnectWiseSelect label="Service board" kind="boards" value={value.boardId} revision={revision} disabled={disabled} onChange={boardId => onChange({ ...value, boardId, statusId: undefined, teamId: undefined })} />
    <ConnectWiseSelect label="Initial ticket status" kind="statuses" value={value.statusId} boardId={value.boardId} revision={revision} disabled={disabled} onChange={statusId => onChange({ ...value, statusId })} />
    <ConnectWiseSelect label="Team" kind="teams" optional value={value.teamId} boardId={value.boardId} revision={revision} disabled={disabled} onChange={teamId => onChange({ ...value, teamId })} />
    <ConnectWiseSelect label="Ticket priority" kind="priorities" value={value.priorityId} revision={revision} disabled={disabled} onChange={priorityId => onChange({ ...value, priorityId })} />
  </div>;
}
