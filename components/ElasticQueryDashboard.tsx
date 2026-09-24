"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Download, GripVertical, LayoutGrid, Pencil, Plus, RadioTower, RefreshCw, Settings2, Trash2 } from "lucide-react";
import { applyTileOrder, moveTileIds } from "@/lib/dashboard-layout";
import { dashboardCsv } from "@/lib/dashboard-csv";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import VulnShell from "@/components/VulnShell";
import Results from "@/components/QueryDashboardResults";
import styles from "./QueryDashboard.module.css";
import { OPEN_VULN_TREND } from "@/lib/elastic-query-templates";
import { inputClass, PanelCard, selectClass } from "@/components/ui";
import { DEFAULT_CROWDSTRIKE, canShowMetrics, isChartDisplay, numericColumn, suggestChart, type CrowdStrikeOptions, type DashboardSource, type DashboardQuery, type ElasticDashboard, type QueryDefinition, type QueryResult } from "@/lib/elastic-dashboard";

type Draft = Omit<QueryDefinition, "id"> & { id?: string };
const newDraft = (): Draft => ({ title: "", query: "", display: "auto", refreshMinutes: 15, enabled: true });
const crowdStrikeDraft = (): Draft => ({ ...newDraft(), source: "crowdstrike", query: "status:['open','reopen']", crowdstrike: { ...DEFAULT_CROWDSTRIKE }, refreshMinutes: 1440 });
const ghostButtonClass = styles.button;
const primaryButtonClass = styles.primaryButton;

async function post(path: string, body?: unknown) {
  return dashboardRequest(path, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}),
  });
}

export default function ElasticQueryDashboard({ initial }: { initial: ElasticDashboard }) {
  const [dashboard, setDashboard] = useState(initial);
  const [connectionOpen, setConnectionOpen] = useState(false);
  const [endpoint, setEndpoint] = useState(initial.endpoint ?? "");
  const [apiKey, setApiKey] = useState("");
  const [connectionSource, setConnectionSource] = useState<DashboardSource>("crowdstrike");
  const [region, setRegion] = useState(initial.crowdstrike?.region ?? "us-1");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [dropId, setDropId] = useState<string | null>(null);
  const [layoutIds, setLayoutIds] = useState<string[] | null>(null);
  const [preview, setPreview] = useState<QueryResult | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [loadError, setLoadError] = useState("");
  const [message, setMessage] = useState("");
  const [now, setNow] = useState<number | null>(null);
  const actionSequence = useRef(0);
  const dashboardVersion = useRef(0);
  const reloadInFlight = useRef(false);
  const dragging = useRef<string | null>(null);
  const reordering = useRef(false);
  const reload = useCallback(async () => {
    if (reloadInFlight.current || dragging.current || reordering.current) return;
    reloadInFlight.current = true;
    try {
      const version = dashboardVersion.current;
      const data = await dashboardRequest<ElasticDashboard>("");
      if (version !== dashboardVersion.current) return;
      if (!data.storageReady) throw new Error("Dashboard storage is unavailable. Previously loaded results are still shown.");
      setDashboard(data); setLoadError("");
      setNow(Date.now());
    } finally { reloadInFlight.current = false; }
  }, []);
  const pending = dashboard.queries.some((query) => !query.result && !query.error);
  useEffect(() => {
    const timer = setInterval(() => { setNow(Date.now()); void reload().catch((err) => setLoadError(err.message)); }, pending ? 3000 : 15_000);
    return () => clearInterval(timer);
  }, [reload, pending]);

  async function action(name: string, work: () => Promise<void>) {
    const sequence = ++actionSequence.current;
    setBusy(name); setError(""); setMessage("");
    try { await work(); } catch (err) {
      if (sequence === actionSequence.current) { setMessage(""); setError(err instanceof Error ? err.message : "The request failed."); }
    }
    finally { if (sequence === actionSequence.current) setBusy(""); }
  }
  async function background(path: "preview", body: unknown) {
    const sequence = actionSequence.current;
    const job = await post(path, body);
    if (sequence !== actionSequence.current) return null;
    if (!job.jobId) return job; // Also tolerates a fast response from an older deployment.
    const deadline = Date.now() + 15 * 60_000;
    while (Date.now() < deadline) {
      if (sequence !== actionSequence.current) return null;
      setMessage("Query queued or running in the background. Execution can take up to five minutes; this page will update when it finishes.");
      await new Promise((resolve) => setTimeout(resolve, 3000));
      if (sequence !== actionSequence.current) return null;
      const status = await dashboardRequest(`jobs/${encodeURIComponent(job.jobId)}`);
      if (sequence !== actionSequence.current) return null;
      if (status.status === "failed") throw new Error(status.error || "The background query failed.");
      if (status.status === "succeeded") { setMessage(""); return status; }
    }
    throw new Error("The query job expired. Reload the dashboard to check saved results, then retry if needed.");
  }
  function edit(query?: DashboardQuery) {
    setDraft(query ? { id: query.id, title: query.title, query: query.query, display: query.display,
      source: query.source, crowdstrike: query.crowdstrike,
      refreshMinutes: query.refreshMinutes, enabled: query.enabled, chart: query.chart } : dashboard.crowdstrike?.connected ? crowdStrikeDraft() : newDraft());
    setPreview(query?.result ?? null); setError(""); setMessage("");
  }
  function moveTile(from: string, to: string) {
    if (busy || reordering.current || !dashboard.canManage || !layoutIds) return;
    setLayoutIds(moveTileIds(applyTileOrder(dashboard.queries, layoutIds).map((query) => query.id), from, to));
  }
  function saveLayout() {
    if (busy || reordering.current || !dashboard.canManage || !layoutIds) return;
    const previous = dashboard.queries.map((query) => query.id);
    const ids = applyTileOrder(dashboard.queries, layoutIds).map((query) => query.id);
    reordering.current = true; dashboardVersion.current++;
    setDashboard((current) => ({ ...current, queries: applyTileOrder(current.queries, ids) }));
    void action("reorder", async () => {
      try {
        const result = await post("order", { ids });
        if (!result.saved) throw new Error("The server did not confirm the tile order. Refresh to check it.");
        setLayoutIds(null);
        setMessage("Tile order saved for everyone.");
      } catch (error) {
        setDashboard((current) => ({ ...current, queries: applyTileOrder(current.queries, previous) }));
        throw error;
      } finally { reordering.current = false; dashboardVersion.current++; }
    });
  }
  function updateCrowdStrike(options: Partial<CrowdStrikeOptions>) {
    if (!draft) return;
    const crowdstrike = { ...DEFAULT_CROWDSTRIKE, ...draft.crowdstrike, ...options };
    if (crowdstrike.view === "patch-worklist" || crowdstrike.view === "severity-counts") {
      crowdstrike.history = false; crowdstrike.groupBy = "none"; crowdstrike.measure = "findings";
    }
    if (crowdstrike.view === "cve-devices") {
      crowdstrike.history = false; crowdstrike.groupBy = "cve"; crowdstrike.measure = "hosts";
    }
    if (crowdstrike.history) crowdstrike.groupBy = "none";
    const category = crowdstrike.history ? "day" : crowdstrike.groupBy === "none" ? undefined : crowdstrike.groupBy;
    setDraft({ ...draft, crowdstrike, chart: category ? { category, value: crowdstrike.measure } : undefined,
      display: crowdstrike.view === "patch-worklist" || crowdstrike.view === "cve-devices" ? "table" : crowdstrike.view === "severity-counts" ? "metrics" : crowdstrike.history ? "line" : "auto" });
    setPreview(null);
  }
  const anyConnected = dashboard.connected || dashboard.crowdstrike?.connected;
  const sourceConnected = (source?: DashboardSource) => source === "crowdstrike" ? dashboard.crowdstrike?.connected : dashboard.connected;
  const visibleQueries = layoutIds ? applyTileOrder(dashboard.queries, layoutIds) : dashboard.queries;

  return <VulnShell variant="dashboard" eyebrow="Exposure / Overview" title="Vulnerability intelligence"
    subtitle="Understand exposure. Prioritize the next patch."
    actions={<div className="flex flex-wrap gap-2">
      <button type="button" className={ghostButtonClass} disabled={Boolean(busy) || Boolean(layoutIds)} onClick={() => action("refresh", async () => {
        if (dashboard.canManage && anyConnected) {
          await post("refresh"); setMessage("Refresh requested. Results will update here as queries finish.");
        }
        await reload();
      })}><RefreshCw size={16} className={busy === "refresh" ? "animate-spin" : ""} />Refresh</button>
      {dashboard.canManage && <>
        {layoutIds ? <>
          <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => { setLayoutIds(null); setMessage("Layout changes canceled."); }}>Cancel</button>
          <button type="button" className={primaryButtonClass} disabled={Boolean(busy)} onClick={saveLayout}>{busy === "reorder" ? "Saving layout…" : "Save layout"}</button>
        </> : <>
          <button type="button" className={ghostButtonClass} disabled={Boolean(busy) || dashboard.queries.length < 2 || Boolean(draft)} onClick={() => { setLayoutIds(dashboard.queries.map((query) => query.id)); setConnectionOpen(false); setDeleting(null); setMessage(""); setError(""); }}><LayoutGrid size={16} />Arrange tiles</button>
          <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => setConnectionOpen((open) => !open)}><Settings2 size={16} />Connections</button>
          <button type="button" className={primaryButtonClass} disabled={!anyConnected || Boolean(busy)} onClick={() => edit()}><Plus size={16} />Add tile</button>
        </>}
      </>}
    </div>}>
    <div className={styles.connections}>
      {[{ name: "CrowdStrike", connected: dashboard.crowdstrike?.connected }, { name: "Elasticsearch", connected: dashboard.connected }].map((source) => <span key={source.name} className={styles.connection}><span className={styles.dot} style={{ background: source.connected ? "#34d399" : "#71717a" }} />{source.name} · {source.connected ? "Configured" : "Not connected"}</span>)}
      <span className={styles.tileCount}>{dashboard.queries.length} saved tiles · Shared dashboard</span>
    </div>
    {error && <p role="alert" className="rounded-xl border border-red-900 bg-red-950/20 p-4 text-sm text-red-300">{error}</p>}
    {loadError && !error && <p role="alert" className="rounded-xl border border-amber-900 bg-amber-950/20 p-4 text-sm text-amber-300">{loadError}</p>}
    {message && <p role="status" className="rounded-xl border border-emerald-900 bg-emerald-950/20 p-4 text-sm text-emerald-300">{message}</p>}
    {busy === "preview" && <button type="button" className={ghostButtonClass} onClick={() => {
      actionSequence.current++; setBusy(""); setMessage("You can add the tile now. The optional preview may finish in the background.");
    }}>Stop waiting for preview</button>}
    {!anyConnected && <div role="status" className="rounded-2xl border border-amber-600/30 bg-amber-950/20 p-4 text-sm text-amber-200">
      {dashboard.storageReady ? "Awaiting the data connection. No live results are available yet." : "Dashboard storage is not available yet."}
      <p className="mt-2">{dashboard.canManage ? "Open Connection to connect CrowdStrike or Elasticsearch." : "Sign in as an organization member to connect a source and manage saved queries."}</p>
    </div>}

    {dashboard.canManage && connectionOpen && <PanelCard eyebrow="Connections" description="Choose the source to connect. Credentials stay encrypted on the server.">
      <label className="mb-5 block text-sm text-zinc-300">Connection source
        <select disabled={Boolean(busy)} className={`${selectClass} mt-2 block`} value={connectionSource} onChange={(event) => setConnectionSource(event.target.value as DashboardSource)}>
          <option value="crowdstrike">CrowdStrike{dashboard.crowdstrike?.connected ? " — connected" : ""}</option>
          <option value="elastic">Elasticsearch{dashboard.connected ? " — connected" : ""}</option>
        </select>
      </label>
      {connectionSource === "crowdstrike" ? <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void action("connection", async () => {
        await post("connections/crowdstrike", { region, clientId, clientSecret }); setClientId(""); setClientSecret("");
        await reload(); setConnectionOpen(false); setMessage("CrowdStrike connection verified. Choose Add query to create an FQL tile.");
      }); }}>
        <label className="block text-sm text-zinc-300">Falcon cloud region
          <select disabled={Boolean(busy)} className={`${selectClass} mt-2 block`} value={region} onChange={(event) => setRegion(event.target.value)}>
            <option value="us-1">US-1</option><option value="us-2">US-2</option><option value="eu-1">EU-1</option><option value="us-gov-1">US-GOV-1</option>
          </select>
        </label>
        <label className="block text-sm text-zinc-300">Client ID
          <input disabled={Boolean(busy)} required value={clientId} onChange={(event) => setClientId(event.target.value)} autoComplete="off" spellCheck={false} className={`${inputClass} mt-2`} />
        </label>
        <label className="block text-sm text-zinc-300">Client secret
          <input disabled={Boolean(busy)} required type="password" value={clientSecret} onChange={(event) => setClientSecret(event.target.value)} autoComplete="new-password" spellCheck={false} className={`${inputClass} mt-2`} />
        </label>
        <p className="text-sm text-zinc-500">Create a Falcon API client with Vulnerabilities: Read. Use the region shown in Falcon’s API Clients and Keys page. Testing reads one page with at most one finding. Replacing this connection clears its cached tiles and starts a new history series.</p>
        <button className={primaryButtonClass} disabled={Boolean(busy) || !dashboard.storageReady}>{busy === "connection" ? "Testing connection…" : "Test and save connection"}</button>
      </form> :
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
      </form>}
    </PanelCard>}

    {dashboard.canManage && draft && <PanelCard eyebrow={draft.id ? "Edit tile" : "Add tile"} description="Add the tile immediately. Its results load on the dashboard. Preview is optional.">
      <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void action("save", async () => {
        const response = await post("queries", draft);
        if (!response.saved || !response.query?.id) throw new Error("The server did not confirm the saved tile. Your form has been kept; check the dashboard before retrying.");
        const tile: DashboardQuery = response.query;
        dashboardVersion.current++;
        setDashboard((current) => ({ ...current, queries: current.queries.some((query) => query.id === tile.id)
          ? current.queries.map((query) => query.id === tile.id ? tile : query) : [...current.queries, tile] }));
        setDraft(null); setPreview(null); setMessage("Tile saved to the dashboard. Results load in the background.");
      }); }}>
        <fieldset disabled={Boolean(busy)} className="space-y-4">
        <label className="block text-sm text-zinc-300">Source
          <select className={`${selectClass} mt-2 block`} value={draft.source ?? "elastic"} onChange={(event) => {
            const replacement = event.target.value === "crowdstrike" ? crowdStrikeDraft() : newDraft();
            setDraft({ ...replacement, id: draft.id, title: draft.title }); setPreview(null);
          }}>
            <option value="elastic">Elasticsearch · ES|QL</option><option value="crowdstrike">CrowdStrike · FQL</option>
          </select>
        </label>
        {!sourceConnected(draft.source) && <p className="text-sm text-amber-300">Open Connection to connect this source before previewing or saving.</p>}
        <label className="block text-sm text-zinc-300">Title
          <input required maxLength={100} className={`${inputClass} mt-2`} value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} placeholder="e.g. Critical vulnerabilities" />
        </label>
        {!draft.id && draft.source !== "crowdstrike" && <div className="space-y-2">
          <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => {
            setDraft({ title: "Open vulnerabilities — daily trend", query: OPEN_VULN_TREND, display: "line", chart: { category: "day", value: "open_vulns" }, refreshMinutes: 1440, enabled: true });
            setPreview(null); setError(""); setMessage("");
          }}>Use daily open trend</button>
          <p className="text-xs text-zinc-500">Starts September 23. The query uses the last confirmed pull; advance report_end to the next UTC day after a successful import. Requires a complete starting state and status changes.</p>
        </div>}
        {draft.source === "crowdstrike" && <div className="space-y-4">
          {!draft.id && <button type="button" className={ghostButtonClass} onClick={() => {
            setDraft({ ...crowdStrikeDraft(), title: "Patch worklist — highest risk first",
              query: "status:['open','reopen']+suppression_info.is_suppressed:false",
              crowdstrike: { ...DEFAULT_CROWDSTRIKE, view: "patch-worklist", top: 25 }, display: "table" });
            setPreview(null); setError(""); setMessage("");
          }}>Use patch worklist</button>}
          {!draft.id && <button type="button" className={`${ghostButtonClass} ml-2`} onClick={() => {
            setDraft({ ...crowdStrikeDraft(), title: "Open vulnerabilities by severity",
              crowdstrike: { ...DEFAULT_CROWDSTRIKE, view: "severity-counts" }, display: "metrics" });
            setPreview(null); setError(""); setMessage("");
          }}>Use severity counts</button>}
          <label className="block text-sm text-zinc-300">Dataset
            <select className={`${selectClass} mt-2 block`} value="vulnerabilities" onChange={() => {}}><option value="vulnerabilities">Vulnerabilities · Spotlight</option></select>
          </label>
          <label className="block text-sm text-zinc-300">View
            <select className={`${selectClass} mt-2 block`} value={draft.crowdstrike?.view ?? "summary"} onChange={(event) => updateCrowdStrike({ view: event.target.value as CrowdStrikeOptions["view"] })}>
              <option value="summary">Summary / chart</option><option value="patch-worklist">Patch worklist</option>
              <option value="severity-counts">Severity counts</option>
              <option value="cve-devices">Affected devices by CVE</option>
            </select>
          </label>
          <div className="flex flex-wrap gap-4">
            {(!draft.crowdstrike?.view || draft.crowdstrike.view === "summary") && <>
            <label className="text-sm text-zinc-300">Measure
              <select className={`${selectClass} mt-2 block`} value={draft.crowdstrike?.measure} onChange={(event) => updateCrowdStrike({ measure: event.target.value as CrowdStrikeOptions["measure"] })}>
                <option value="findings">Finding count</option><option value="cves">Unique CVEs</option><option value="hosts">Unique affected hosts</option>
              </select>
            </label>
            <label className="text-sm text-zinc-300">Group by
              <select disabled={draft.crowdstrike?.history} className={`${selectClass} mt-2 block`} value={draft.crowdstrike?.groupBy} onChange={(event) => updateCrowdStrike({ groupBy: event.target.value as CrowdStrikeOptions["groupBy"] })}>
                <option value="none">None · total</option><option value="host">Host</option><option value="severity">Severity</option><option value="priority">GMI priority (P1/P2/P3)</option><option value="status">Status</option><option value="cve">CVE</option>
              </select>
            </label>
            </>}
            {(draft.crowdstrike?.view === "patch-worklist" || draft.crowdstrike?.groupBy !== "none") && <label className="text-sm text-zinc-300">{draft.crowdstrike?.view === "patch-worklist" ? "Top findings" : draft.crowdstrike?.view === "cve-devices" ? "Top CVEs" : "Top groups"}
              <select className={`${selectClass} mt-2 block`} value={draft.crowdstrike?.top} onChange={(event) => updateCrowdStrike({ top: Number(event.target.value) })}>
                {[10, 25, 50, 100].map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>}
          </div>
          {draft.crowdstrike?.view === "cve-devices" ? <p className="text-xs text-zinc-500">One row per CVE. Counts unique affected devices across open/reopened findings. Sorted by CVSS severity, then affected devices. Each severity is collected completely before ranking; lower severities are skipped once higher severities fill the table.</p> : draft.crowdstrike?.view === "severity-counts" ? <p className="text-xs text-zinc-500">Critical, High, Medium, Low, None and Unknown together. Uses CrowdStrike's CVSS severity totals without downloading every finding. Counts vulnerability instances, not unique CVEs. The preset includes open/reopened findings, including suppressed findings; add a suppression filter if needed.</p> : draft.crowdstrike?.view === "patch-worklist" ? <p className="text-xs text-zinc-500">Open P1–P3 findings, one row per finding and device. Sorted by GMI priority, risk score, then affected devices. The preset excludes suppressed findings. All matching pages are collected before choosing the top rows. Use Daily refresh for broad filters.</p> : <>
            <label className="flex items-center gap-2 text-sm text-zinc-300"><input type="checkbox" checked={draft.crowdstrike?.history ?? false} onChange={(event) => updateCrowdStrike({ history: event.target.checked })} />Save daily history of the total</label>
            <p className="text-xs text-zinc-500">FQL filters findings; the app calculates the measure across every returned page. History starts with the first saved collection and shows the latest successful count per UTC day. Each filter and measure has separate history. Missing days appear as gaps.</p>
          </>}
          {draft.crowdstrike?.groupBy === "priority" && <p className="text-xs text-zinc-500">Uses your GMI risk rules, including exploit status, KEV, ExPRT, CVSS, exploitability and severity. “Other” includes findings below P3; missing risk fields contribute no points.</p>}
          <a className="text-sm text-red-300 underline" href="https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/" target="_blank" rel="noreferrer">Supported CrowdStrike FQL fields</a>
        </div>}
        <label className="block text-sm text-zinc-300">{draft.source === "crowdstrike" ? "FQL filter" : "ES|QL"}
          <textarea disabled={Boolean(busy)} required rows={draft.source === "crowdstrike" ? 3 : 8} maxLength={draft.source === "crowdstrike" ? 4000 : 16000} value={draft.query} onChange={(event) => { setDraft({ ...draft, query: event.target.value, chart: undefined }); setPreview(null); }}
            className="mt-2 w-full rounded-2xl border border-zinc-800 bg-[#0b0b0b] p-4 font-mono text-sm text-white outline-none focus:border-red-800" placeholder={draft.source === "crowdstrike" ? "status:['open','reopen']" : "FROM your-index-* | STATS count = COUNT(*)"} spellCheck={false} />
        </label>
        <div className="flex flex-wrap items-end gap-4">
          <label className="text-sm text-zinc-300">Display
            <select disabled={draft.source === "crowdstrike" && ["patch-worklist", "cve-devices"].includes(draft.crowdstrike?.view ?? "")} className={`${selectClass} mt-2 block`} value={draft.display} onChange={(event) => setDraft({ ...draft, display: event.target.value as Draft["display"], chart: draft.chart ?? (preview ? suggestChart(preview) : undefined) })}>
              <option value="auto">Automatic</option><option value="metrics">Number cards</option><option value="table">Table</option>
              {draft.crowdstrike?.view !== "severity-counts" && <><option value="bar">Bar chart</option><option value="line">Line chart</option><option value="doughnut">Doughnut chart</option></>}
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
          </div> : <div className="flex flex-wrap gap-4">
            <label className="text-sm text-zinc-300">Category / X column
              <input required className={`${inputClass} mt-2 block`} placeholder="e.g. host or day" value={draft.chart?.category ?? ""} onChange={(event) => setDraft({ ...draft, chart: { category: event.target.value, value: draft.chart?.value ?? "" } })} />
            </label>
            <label className="text-sm text-zinc-300">Numeric / Y column
              <input required className={`${inputClass} mt-2 block`} placeholder="e.g. findings" value={draft.chart?.value ?? ""} onChange={(event) => setDraft({ ...draft, chart: { category: draft.chart?.category ?? "", value: event.target.value } })} />
            </label>
            <p className="w-full text-xs text-zinc-500">Enter the column names, or optionally preview to choose from the results.</p>
          </div>}
        </div>}
        <div className="flex flex-wrap gap-3">
          <button type="button" className={ghostButtonClass} disabled={Boolean(busy) || !draft.query.trim() || !sourceConnected(draft.source)} onClick={() => action("preview", async () => {
            const data = await background("preview", { id: draft.id, source: draft.source, query: draft.query, crowdstrike: draft.crowdstrike });
            if (!data) return;
            setPreview(data.result);
            setDraft((current) => current ? { ...current, chart: current.chart ?? suggestChart(data.result) } : current);
          })}>{busy === "preview" ? "Loading preview…" : "Preview (optional)"}</button>
          <button className={primaryButtonClass} disabled={Boolean(busy) || !sourceConnected(draft.source) || (isChartDisplay(draft.display) && (!draft.chart?.category || !draft.chart?.value))}>{busy === "save" ? "Saving tile…" : draft.id ? "Save changes" : "Add to dashboard"}</button>
          <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => { setDraft(null); setPreview(null); }}>Cancel</button>
        </div>
        {preview && <div className="border-t border-zinc-800 pt-4"><p className="mb-3 text-sm text-zinc-400">Preview</p><Results result={preview} display={draft.display} chart={draft.chart} />{preview.note && <p className="mt-3 text-xs text-zinc-500">{preview.note}</p>}</div>}
        </fieldset>
      </form>
    </PanelCard>}

    {layoutIds && <p id="tile-order-help" className={styles.arrangeHelp}><GripVertical size={16} />Drag tiles by their handles or use the arrows. Save layout applies the order for everyone.</p>}
    {!dashboard.queries.length && <div className="rounded-xl border border-zinc-800 p-8 text-center text-zinc-400">No saved tiles yet. {dashboard.canManage && "Choose Add tile to create your first view."}</div>}
    <div className={`${styles.board} ${layoutIds ? styles.arranging : ""}`}>
    {visibleQueries.map((query, index) => {
      const stale = query.refreshedAt && now !== null && now - Date.parse(query.refreshedAt) > query.refreshMinutes * 2 * 60_000;
      const metrics = query.result && query.display !== "table" && !isChartDisplay(query.display) && canShowMetrics(query.result);
      const wide = query.display === "table" || query.crowdstrike?.view === "cve-devices" || query.crowdstrike?.view === "patch-worklist" || (query.result && (metrics ? query.result.columns.length >= 4 : !isChartDisplay(query.display)));
      return <section key={query.id} aria-label={query.title} className={`${styles.tile} ${wide ? styles.wide : ""} ${draggedId === query.id ? styles.dragging : ""} ${dropId === query.id && draggedId !== query.id ? styles.drop : ""}`}
        onDragOver={(event) => { if (layoutIds && dragging.current && !busy) { event.preventDefault(); event.dataTransfer.dropEffect = "move"; setDropId(query.id); } }}
        onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDropId((current) => current === query.id ? null : current); }}
        onDrop={(event) => {
          const from = dragging.current; if (!from) return;
          event.preventDefault(); dragging.current = null; setDraggedId(null); setDropId(null); moveTile(from, query.id);
        }}>
      {layoutIds && <div className={styles.movebar}>
        <button type="button" className={`${ghostButtonClass} ${styles.grip}`} draggable={!busy} disabled={Boolean(busy)} aria-label={`Drag to reorder ${query.title}`} aria-describedby="tile-order-help"
          onDragStart={(event) => { dragging.current = query.id; dashboardVersion.current++; setDraggedId(query.id); event.dataTransfer.effectAllowed = "move"; event.dataTransfer.setData("text/plain", query.id); }}
          onDragEnd={() => { dragging.current = null; setDraggedId(null); setDropId(null); }}
          onKeyDown={(event) => { if (event.key === "ArrowUp" || event.key === "ArrowDown") { event.preventDefault(); const target = visibleQueries[index + (event.key === "ArrowUp" ? -1 : 1)]; if (target) moveTile(query.id, target.id); } }}><GripVertical size={16} />Move tile</button>
        <button type="button" className={ghostButtonClass} disabled={Boolean(busy) || index === 0} aria-label={`Move ${query.title} earlier`} onClick={() => moveTile(query.id, visibleQueries[index - 1].id)}><ArrowUp size={14} />Earlier</button>
        <button type="button" className={ghostButtonClass} disabled={Boolean(busy) || index === visibleQueries.length - 1} aria-label={`Move ${query.title} later`} onClick={() => moveTile(query.id, visibleQueries[index + 1].id)}><ArrowDown size={14} />Later</button>
      </div>}
      <header className={styles.tileHeader}>
        <div className={styles.tileHeading}><h2>{query.title}</h2><p className={styles.source}><RadioTower size={12} />{query.source === "crowdstrike" ? "CrowdStrike · Vulnerabilities" : "Elasticsearch"}</p></div>
        <div className={styles.tileActions}>
          {query.result && <button type="button" className={ghostButtonClass} onClick={() => {
            const url = URL.createObjectURL(new Blob([dashboardCsv(query.result!)], { type: "text/csv;charset=utf-8" }));
            const link = document.createElement("a"); link.href = url; link.download = `${query.title.replace(/[^a-z0-9-]/gi, "-").slice(0, 80) || "dashboard-tile"}.csv`;
            link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
          }}><Download size={14} />CSV</button>}
          {dashboard.canManage && !layoutIds && <>
            <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => edit(query)}><Pencil size={14} />Edit</button>
            <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => setDeleting(query.id)} aria-label={`Delete ${query.title}`}><Trash2 size={14} />Delete</button>
          </>}
        </div>
      </header>
      <div className={styles.tileContent}>
        {deleting === query.id && <div role="alert" className="mb-4 rounded-xl border border-red-900 p-4 text-sm text-zinc-300">
          <p>Delete this shared dashboard tile and its saved history? Source findings are unaffected.</p>
          <div className="mt-3 flex gap-2">
            <button type="button" className={primaryButtonClass} disabled={Boolean(busy)} onClick={() => action("delete", async () => {
              const data = await dashboardRequest(`queries/${encodeURIComponent(query.id)}`, { method: "DELETE" });
              if (!data.deleted) throw new Error("The server did not confirm deletion. Check the dashboard before retrying.");
              dashboardVersion.current++;
              setDashboard((current) => ({ ...current, queries: current.queries.filter((tile) => tile.id !== query.id) }));
              if (draft?.id === query.id) { setDraft(null); setPreview(null); }
              setDeleting(null); setMessage("Tile deleted.");
            })}>{busy === "delete" ? "Deleting…" : "Delete tile"}</button>
            <button type="button" className={ghostButtonClass} disabled={Boolean(busy)} onClick={() => setDeleting(null)}>Cancel</button>
          </div>
        </div>}
        {query.error && <p className="mb-4 text-sm text-amber-300">{query.error} {query.result ? "Showing the last successful result." : "No successful result yet."}</p>}
        {stale && !query.error && <p className="mb-4 text-sm text-amber-300">These results are older than two refresh intervals.</p>}
        {query.result ? <Results result={query.result} display={query.display} chart={query.chart} /> : !query.error && <p role="status" className="flex items-center gap-2 py-5 text-zinc-400"><RefreshCw size={16} className="animate-spin" />Loading results in the background…</p>}
        {query.result?.note && <p className="mt-3 text-xs text-zinc-500">{query.result.note}</p>}
        {query.id === "asset-coverage" && query.source !== "crowdstrike" && <p className="mt-2 text-xs text-zinc-500">Asset inventory coverage, not vulnerability counts. Records from the last 25 hours; assets last seen within seven days. IDs recorded as both managed and unmanaged can count in both categories.</p>}
      </div>
      <footer className={styles.tileFooter}><span>{query.refreshedAt ? `Updated ${new Date(query.refreshedAt).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC")}` : "No successful result yet"}</span><span>{query.enabled ? (query.refreshMinutes === 1440 ? "Daily refresh" : `Every ${query.refreshMinutes} min`) : "Automatic refresh paused"}</span></footer>
      </section>;
    })}
    </div>
  </VulnShell>;
}
