"use client";

import { useCallback, useEffect, useState } from "react";
import { Database, Pencil, Plus, RefreshCw, Settings2 } from "lucide-react";
import VulnShell from "@/components/VulnShell";
import ElasticResultChart from "@/components/ElasticResultChart";
import { OPEN_VULN_TREND } from "@/lib/elastic-query-templates";
import { ghostButtonClass, inputClass, PanelCard, primaryButtonClass, selectClass, StatCard } from "@/components/ui";
import { canShowMetrics, columnLabel, isChartDisplay, numericColumn, suggestChart, type DashboardQuery, type ElasticDashboard, type QueryDefinition, type QueryResult } from "@/lib/elastic-dashboard";

type Draft = Omit<QueryDefinition, "id"> & { id?: string };
const newDraft = (): Draft => ({ title: "", query: "", display: "auto", refreshMinutes: 15, enabled: true });

function formatValue(value: string | number | boolean | null, column: string): string {
  if (value === null) return "—";
  if (typeof value === "number") {
    const formatted = value.toLocaleString("en-US", { maximumFractionDigits: 2 });
    return /(?:_pct|_percent|percentage)$/i.test(column) ? `${formatted}%` : formatted;
  }
  return String(value);
}

function Results({ result, display, chart }: { result: QueryResult; display: QueryDefinition["display"]; chart?: QueryDefinition["chart"] }) {
  if (isChartDisplay(display)) return <ElasticResultChart result={result} definition={{ display, chart }} />;
  if (display !== "table" && canShowMetrics(result)) {
    return <div className="grid gap-4 sm:grid-cols-2 2xl:grid-cols-3">
      {result.columns.map((column, index) => <StatCard key={column.name} label={columnLabel(column.name)}
        value={formatValue(result.rows[0][index], column.name)} sublabel="Latest successful query" icon={<Database size={22} />} />)}
    </div>;
  }
  return <div className="overflow-x-auto">
    <table className="w-full text-left text-sm">
      <caption className="sr-only">ES|QL query results</caption>
      <thead><tr>{result.columns.map((column) => <th key={column.name} scope="col" className="border-b border-zinc-800 px-3 py-3 font-medium text-zinc-400">{columnLabel(column.name)}</th>)}</tr></thead>
      <tbody>{result.rows.map((row, index) => <tr key={index} className="border-b border-zinc-900">
        {row.map((value, cell) => <td key={cell} className="max-w-md break-words px-3 py-3 text-zinc-200">{formatValue(value, result.columns[cell].name)}</td>)}
      </tr>)}</tbody>
    </table>
    {!result.rows.length && <p className="py-6 text-zinc-400">The query returned no rows.</p>}
    {result.truncated && <p className="mt-3 text-sm text-amber-300">Showing the first 100 rows. Narrow or aggregate the query to show the full result.</p>}
  </div>;
}

async function post(path: string, body?: unknown) {
  const response = await fetch(`/api/elastic-dashboard/${path}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "The request failed.");
  return data;
}

export default function ElasticQueryDashboard({ initial }: { initial: ElasticDashboard }) {
  const [dashboard, setDashboard] = useState(initial);
  const [connectionOpen, setConnectionOpen] = useState(false);
  const [endpoint, setEndpoint] = useState(initial.endpoint ?? "");
  const [apiKey, setApiKey] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [preview, setPreview] = useState<QueryResult | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [now, setNow] = useState<number | null>(null);
  const reload = useCallback(async () => {
    const response = await fetch("/api/elastic-dashboard", { cache: "no-store" });
    if (!response.ok) throw new Error(response.status === 401 ? "Your session expired. Sign in again." : "Unable to load results. Previously loaded results are still shown.");
    const data: ElasticDashboard = await response.json();
    if (!data.storageReady) throw new Error("Dashboard storage is unavailable. Previously loaded results are still shown.");
    setDashboard(data);
    setNow(Date.now());
  }, []);
  useEffect(() => {
    const timer = setInterval(() => { setNow(Date.now()); void reload().catch((err) => setError(err.message)); }, 15_000);
    return () => clearInterval(timer);
  }, [reload]);

  async function action(name: string, work: () => Promise<void>) {
    setBusy(name); setError(""); setMessage("");
    try { await work(); } catch (err) { setMessage(""); setError(err instanceof Error ? err.message : "The request failed."); }
    finally { setBusy(""); }
  }
  async function background(path: "preview" | "queries", body: unknown) {
    const job = await post(path, body);
    if (!job.jobId) return job; // Also tolerates a fast response from an older deployment.
    const deadline = Date.now() + 15 * 60_000;
    while (Date.now() < deadline) {
      setMessage("Query queued or running in the background. Execution can take up to five minutes; this page will update when it finishes.");
      await new Promise((resolve) => setTimeout(resolve, 3000));
      const response = await fetch(`/api/elastic-dashboard/jobs/${encodeURIComponent(job.jobId)}`, { cache: "no-store" });
      const status = await response.json();
      if (!response.ok || status.status === "failed") throw new Error(status.error || "The background query failed.");
      if (status.status === "succeeded") { setMessage(""); return status; }
    }
    throw new Error("The query job expired. Reload the dashboard to check saved results, then retry if needed.");
  }
  function edit(query?: DashboardQuery) {
    setDraft(query ? { id: query.id, title: query.title, query: query.query, display: query.display,
      refreshMinutes: query.refreshMinutes, enabled: query.enabled, chart: query.chart } : newDraft());
    setPreview(query?.result ?? null); setError(""); setMessage("");
  }

  return <VulnShell eyebrow="Elasticsearch" title="Elastic dashboard"
    subtitle="Save ES|QL queries as dashboard tiles. Results refresh automatically in the app."
    actions={<div className="flex flex-wrap gap-2">
      <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => action("refresh", async () => {
        if (dashboard.canManage && dashboard.connected) {
          await post("refresh"); setMessage("Refresh requested. Results will update here as queries finish.");
        }
        await reload();
      })}><RefreshCw size={16} className={busy === "refresh" ? "animate-spin" : ""} />Refresh</button>
      {dashboard.canManage && <>
        <button type="button" className={ghostButtonClass} onClick={() => setConnectionOpen((open) => !open)}><Settings2 size={16} />Connection</button>
        <button type="button" className={primaryButtonClass} disabled={!dashboard.connected || Boolean(busy)} onClick={() => edit()}><Plus size={16} />Add query</button>
      </>}
    </div>}>
    {error && <p role="alert" className="rounded-xl border border-red-900 bg-red-950/20 p-4 text-sm text-red-300">{error}</p>}
    {message && <p role="status" className="rounded-xl border border-emerald-900 bg-emerald-950/20 p-4 text-sm text-emerald-300">{message}</p>}
    {!dashboard.connected && <div role="status" className="rounded-2xl border border-amber-600/30 bg-amber-950/20 p-4 text-sm text-amber-200">
      {dashboard.storageReady ? "Awaiting the data connection. No live results are available yet." : "Dashboard storage is not available yet."}
      <p className="mt-2">{dashboard.canManage ? "Open Connection to add your Elasticsearch endpoint and read-only API key." : "Sign in as an organization member to connect Elasticsearch and manage saved queries."}</p>
    </div>}

    {dashboard.canManage && connectionOpen && <PanelCard eyebrow="Elasticsearch connection" description="Use the Elasticsearch HTTPS endpoint, not the Kibana dashboard address.">
      <form onSubmit={(event) => { event.preventDefault(); void action("connection", async () => {
        await post("connection", { endpoint, apiKey }); setApiKey(""); await reload(); setConnectionOpen(false);
        setMessage("Connection verified and saved. The first query is refreshing.");
      }); }} className="space-y-4">
        <label className="block text-sm text-zinc-300">Elasticsearch endpoint
          <input type="url" required value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="https://your-deployment.es.region.aws.found.io" className={`${inputClass} mt-2`} />
        </label>
        <label className="block text-sm text-zinc-300">Encoded API key
          <input type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} autoComplete="new-password" spellCheck={false}
            placeholder={dashboard.connected ? "Leave blank to keep the key for this same endpoint" : "Paste the read-only API key"} className={`${inputClass} mt-2`} />
        </label>
        <p className="text-sm text-zinc-500">Paste the encoded key only, without the “ApiKey” prefix. The key is encrypted when saved and is never returned to the browser. Grant read access only to the indices these queries need. The connection test runs the asset coverage query.</p>
        <button className={primaryButtonClass} disabled={Boolean(busy) || !dashboard.storageReady}>{busy === "connection" ? "Testing connection…" : "Test and save connection"}</button>
      </form>
    </PanelCard>}

    {dashboard.canManage && draft && <PanelCard eyebrow={draft.id ? "Edit query" : "Add query"} description="Preview your ES|QL, then choose number cards, a table, or a chart.">
      <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void action("save", async () => {
        await background("queries", draft); await reload(); setDraft(null); setPreview(null); setMessage("Query saved. It will refresh automatically.");
      }); }}>
        <label className="block text-sm text-zinc-300">Title
          <input required maxLength={100} className={`${inputClass} mt-2`} value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} placeholder="e.g. Critical vulnerabilities" />
        </label>
        {!draft.id && <div className="space-y-2">
          <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => {
            setDraft({ title: "Open vulnerabilities — daily trend", query: OPEN_VULN_TREND, display: "line", refreshMinutes: 1440, enabled: true });
            setPreview(null); setError(""); setMessage("");
          }}>Use daily open trend</button>
          <p className="text-xs text-zinc-500">Carries the last known status forward for 30 days. Requires complete retained status history and a stable finding ID. Today is partial.</p>
        </div>}
        <label className="block text-sm text-zinc-300">ES|QL
          <textarea disabled={Boolean(busy)} required rows={8} maxLength={16000} value={draft.query} onChange={(event) => { setDraft({ ...draft, query: event.target.value, chart: undefined }); setPreview(null); }}
            className="mt-2 w-full rounded-2xl border border-zinc-800 bg-[#0b0b0b] p-4 font-mono text-sm text-white outline-none focus:border-red-800" placeholder="FROM your-index-* | STATS count = COUNT(*)" spellCheck={false} />
        </label>
        <div className="flex flex-wrap items-end gap-4">
          <label className="text-sm text-zinc-300">Display
            <select className={`${selectClass} mt-2 block`} value={draft.display} onChange={(event) => setDraft({ ...draft, display: event.target.value as Draft["display"], chart: draft.chart ?? (preview ? suggestChart(preview) : undefined) })}>
              <option value="auto">Automatic</option><option value="metrics">Number cards</option><option value="table">Table</option>
              <option value="bar">Bar chart</option><option value="line">Line chart</option><option value="doughnut">Doughnut chart</option>
            </select>
          </label>
          <label className="text-sm text-zinc-300">Refresh every
            <select className={`${selectClass} mt-2 block`} value={draft.refreshMinutes} onChange={(event) => setDraft({ ...draft, refreshMinutes: Number(event.target.value) })}>
              {[5, 15, 30, 60, 1440].map((minutes) => <option key={minutes} value={minutes}>{minutes === 1440 ? "Daily" : `${minutes} minutes`}</option>)}
            </select>
          </label>
          <label className="flex h-[52px] items-center gap-2 text-sm text-zinc-300"><input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })} />Automatic refresh</label>
        </div>
        {isChartDisplay(draft.display) && <div className="rounded-xl border border-zinc-800 p-4">
          <p className="mb-3 text-sm text-zinc-400">Return one row per category and a numeric value, such as tier and findings. For trends, return a time bucket and a count.</p>
          {preview ? <div className="flex flex-wrap gap-4">
            <label className="text-sm text-zinc-300">Category / X axis
              <select required className={`${selectClass} mt-2 block`} value={draft.chart?.category ?? ""} onChange={(event) => setDraft({ ...draft, chart: { category: event.target.value, value: draft.chart?.value ?? "" } })}>
                <option value="">Choose a column</option>
                {preview.columns.map((column) => <option key={column.name} value={column.name}>{column.name}</option>)}
              </select>
            </label>
            <label className="text-sm text-zinc-300">Value / Y axis
              <select required className={`${selectClass} mt-2 block`} value={draft.chart?.value ?? ""} onChange={(event) => setDraft({ ...draft, chart: { category: draft.chart?.category ?? "", value: event.target.value } })}>
                <option value="">Choose a numeric column</option>
                {preview.columns.filter((column) => numericColumn(column.type) && column.name !== draft.chart?.category).map((column) => <option key={column.name} value={column.name}>{column.name}</option>)}
              </select>
            </label>
          </div> : <p className="text-sm text-amber-300">Click Preview results to load the available columns.</p>}
        </div>}
        <div className="flex flex-wrap gap-3">
          <button type="button" className={ghostButtonClass} disabled={Boolean(busy) || !draft.query.trim()} onClick={() => action("preview", async () => {
            const data = await background("preview", { query: draft.query }); setPreview(data.result);
            setDraft((current) => current ? { ...current, chart: current.chart ?? suggestChart(data.result) } : current);
          })}>{busy === "preview" ? "Running query…" : "Preview results"}</button>
          <button className={primaryButtonClass} disabled={Boolean(busy) || (isChartDisplay(draft.display) && (!draft.chart?.category || !draft.chart?.value))}>{busy === "save" ? "Validating and saving…" : "Save query"}</button>
          <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => { setDraft(null); setPreview(null); }}>Cancel</button>
        </div>
        {preview && <div className="border-t border-zinc-800 pt-4"><p className="mb-3 text-sm text-zinc-400">Preview</p><Results result={preview} display={draft.display} chart={draft.chart} /></div>}
      </form>
    </PanelCard>}

    {dashboard.queries.map((query) => {
      const stale = query.refreshedAt && now !== null && now - Date.parse(query.refreshedAt) > query.refreshMinutes * 2 * 60_000;
      return <PanelCard key={query.id} eyebrow={query.title}
        description={query.enabled ? (query.refreshMinutes === 1440 ? "Refreshes daily" : `Refreshes every ${query.refreshMinutes} minutes`) : "Automatic refresh paused"}
        actions={dashboard.canManage && <button type="button" className={ghostButtonClass} disabled={Boolean(busy) || !dashboard.connected} onClick={() => edit(query)}><Pencil size={14} />Edit</button>}>
        {query.error && <p className="mb-4 text-sm text-amber-300">{query.error} {query.result ? "Showing the last successful result." : "No successful result yet."}</p>}
        {stale && !query.error && <p className="mb-4 text-sm text-amber-300">These results are older than two refresh intervals.</p>}
        {query.result ? <Results result={query.result} display={query.display} chart={query.chart} /> : <p className="py-5 text-zinc-400">Waiting for the first successful query.</p>}
        <p className="mt-4 text-xs text-zinc-500">Last successful query: {query.refreshedAt ? new Date(query.refreshedAt).toISOString().replace("T", " ").replace("Z", " UTC") : "not yet available"}</p>
        {query.id === "asset-coverage" && <p className="mt-2 text-xs text-zinc-500">Asset inventory coverage, not vulnerability counts. Records from the last 25 hours; assets last seen within seven days. IDs recorded as both managed and unmanaged can count in both categories.</p>}
      </PanelCard>;
    })}
  </VulnShell>;
}
