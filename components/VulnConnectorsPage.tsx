"use client";

import React, { useEffect, useState } from "react";
import { ExternalLink, RefreshCw, Upload } from "lucide-react";
import {
  IconClipboardCheck,
  IconCloudLock,
  IconDatabaseCog,
  IconDeviceLaptop,
  IconPackage,
  IconRadar,
  IconShieldSearch,
  IconSpider,
  IconTopologyStar3,
} from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, Pill } from "@/components/ui";
import type { Connector, ConnectorStatus } from "@/lib/types";

type CardData = {
  id: string;
  name: string;
  vendor: string;
  kind: string;
  description: string;
  capabilities: string[];
  envVars: string[];
  configured: boolean;
  status: ConnectorStatus;
  docsUrl: string;
};

type TidalSyncStatus = {
  running: boolean;
  phase: string;
  companiesTotal: number;
  companiesDone: number;
  currentCompany: string;
  assetsFound: number;
  startedAt: number;
  finishedAt: number | null;
  result: unknown;
  error: string | null;
};

const cardIcon: Record<string, React.ElementType> = {
  nessus: IconRadar,
  vulners: IconPackage,
  crowdstrike: IconShieldSearch,
  defender: IconShieldSearch,
  qualys: IconCloudLock,
  spiderfoot: IconSpider,
  artemis: IconTopologyStar3,
  burp: IconShieldSearch,
  nmap: IconRadar,
  tidal: IconDatabaseCog,
  intune: IconDeviceLaptop,
  "crowdstrike-devices": IconShieldSearch,
  grc: IconClipboardCheck,
};

// Connectors with a reachability probe get a live health dot.
const HEALTH_ENDPOINTS: Record<string, string> = {
  nessus: "/api/nessus/health",
  artemis: "/api/artemis/health",
  spiderfoot: "/api/spiderfoot/health",
  burp: "/api/burp/health",
  nmap: "/api/nmap/health",
  vulners: "/api/vulners/health",
};

// Connectors with a pull/import endpoint get a "Sync now" button.
const SYNC_ENDPOINTS: Record<string, string> = {
  nessus: "/api/nessus/import",
  crowdstrike: "/api/crowdstrike/spotlight-import",
  "crowdstrike-devices": "/api/crowdstrike/import",
  defender: "/api/defender/import",
  spiderfoot: "/api/spiderfoot/import",
  artemis: "/api/artemis/import",
  tidal: "/api/tidal/import",
  intune: "/api/intune/import",
  burp: "/api/burp/import",
  nmap: "/api/nmap/import",
  vulners: "/api/vulners/import",
};

// Render a human summary from the various import result shapes.
function summarizeSync(result: any): string {
  if (!result || typeof result !== "object") return "Sync complete.";
  const parts: string[] = [];
  const n = (v: unknown) => (typeof v === "number" ? v : null);
  if (n(result.findingsImported) != null) parts.push(`${result.findingsImported} findings`);
  if (n(result.scansImported) != null) parts.push(`${result.scansImported} scans`);
  if (n(result.rowsParsed) != null) parts.push(`${result.rowsParsed} rows`);
  if (n(result.issuesParsed) != null) parts.push(`${result.issuesParsed} issues`);
  if (n(result.hostsParsed) != null) parts.push(`${result.hostsParsed} hosts`);
  if (n(result.assetsUpdated)) parts.push(`${result.assetsUpdated} assets updated`);
  if (n(result.assetsUpserted) != null) parts.push(`${result.assetsUpserted} assets`);
  if (n(result.companiesCreated)) parts.push(`${result.companiesCreated} new companies`);
  if (n(result.findingsRescored)) parts.push(`${result.findingsRescored} findings repriced`);
  if (n(result.companiesMatched) != null) parts.push(`${result.companiesMatched} companies`);
  if (n(result.cvesEnriched) != null) parts.push(`${result.cvesEnriched} CVEs enriched`);
  if (n(result.findingsUpdated) != null) parts.push(`${result.findingsUpdated} findings updated`);
  if (n(result.exploitsFound)) parts.push(`${result.exploitsFound} with exploits`);
  const skipped = Array.isArray(result.skipped) ? result.skipped.length : 0;
  if (skipped) parts.push(`${skipped} skipped`);
  return parts.length ? `Synced — ${parts.join(", ")}.` : "Sync complete.";
}

function summarizeOsint(result: any): string {
  if (!result || typeof result !== "object") return "OSINT scans launched.";
  const c = result.companies ?? 0;
  const d = result.domainsTotal ?? 0;
  const a = result.artemis?.launched ?? 0;
  const sf = result.spiderfoot?.launched ?? 0;
  let msg = `Launched for ${c} customer${c === 1 ? "" : "s"} (${d} domain${d === 1 ? "" : "s"}) — Artemis: ${a}, SpiderFoot: ${sf}.`;
  const errs = Array.isArray(result.errors) ? result.errors.length : 0;
  if (errs) msg += ` ${errs} error${errs === 1 ? "" : "s"}.`;
  return msg;
}

type OsintPreview = {
  companies: number;
  domainsTotal: number;
  perCompany: { company: string; domains: string[] }[];
};

// Banner action: fan out Artemis + SpiderFoot OSINT scans across all customers.
function OsintLaunchBanner() {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [preview, setPreview] = useState<OsintPreview | null>(null);
  const [showTargets, setShowTargets] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [enrichMsg, setEnrichMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function runEnrich() {
    if (enriching) return;
    setEnriching(true);
    setEnrichMsg(null);
    try {
      const res = await fetch("/api/enrich", { method: "POST" });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || json.error) {
        setEnrichMsg({ ok: false, text: json.error ?? `Failed (HTTP ${res.status})` });
      } else {
        const r = json.result ?? {};
        const base = `Threat intel refreshed — ${r.realCveFindings ?? 0} CVE-based findings · ${r.cvesWithEpss ?? 0} with EPSS · ${r.ransomwareLinked ?? 0} ransomware-linked · ${r.cvssFilled ?? 0} CVSS filled from NVD · ${r.findingsUpdated ?? 0} re-scored.`;
        const hint =
          (r.realCveFindings ?? 0) === 0
            ? " No CVE-based findings yet — KEV/EPSS apply to scanner findings (Nessus/Defender). OSINT findings are scored on exposure."
            : "";
        setEnrichMsg({ ok: true, text: base + hint });
      }
    } catch (err) {
      setEnrichMsg({ ok: false, text: err instanceof Error ? err.message : "Failed." });
    } finally {
      setEnriching(false);
    }
  }

  useEffect(() => {
    void fetch("/api/osint/preview", { cache: "no-store" })
      .then((r) => r.json())
      .then((j) => setPreview(j.preview ?? null))
      .catch(() => undefined);
  }, []);

  async function run() {
    if (busy) return;
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch("/api/osint/launch", { method: "POST" });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || json.error) {
        setMsg({ ok: false, text: json.error ?? `Failed (HTTP ${res.status})` });
      } else {
        const r = json.result;
        const total = (r?.artemis?.launched ?? 0) + (r?.spiderfoot?.launched ?? 0);
        setMsg({ ok: total > 0, text: summarizeOsint(r) });
      }
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Failed." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-2xl border border-[rgba(179,14,20,0.22)] bg-[#0b0b0b] p-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold text-white">
            OSINT sweep &amp; threat intel
          </h2>
          <p className="mt-1 text-sm text-zinc-400">
            Launch Artemis + SpiderFoot against every customer&apos;s root domains
            for supplemental attack-surface context, and refresh CISA KEV + EPSS to
            re-score every finding. Run either on demand.
          </p>
        </div>
        <div className="flex shrink-0 flex-col gap-2 sm:flex-row">
          <button
            type="button"
            onClick={runEnrich}
            disabled={enriching}
            title="Refresh CISA KEV + EPSS and re-score findings"
            className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <RefreshCw size={15} className={enriching ? "animate-spin" : ""} />
            {enriching ? "Refreshing…" : "Refresh threat intel"}
          </button>
          <button
            type="button"
            onClick={run}
            disabled={busy || (preview != null && preview.companies === 0)}
            className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.14)] px-4 py-2 text-sm font-medium text-[#ff4d57] transition hover:bg-[rgba(179,14,20,0.24)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            <RefreshCw size={15} className={busy ? "animate-spin" : ""} />
            {busy ? "Launching…" : "Run OSINT scans (all customers)"}
          </button>
        </div>
      </div>

      {enrichMsg ? (
        <div
          className={`mt-3 rounded-lg border px-3 py-2 text-xs ${
            enrichMsg.ok
              ? "border-emerald-900/60 bg-emerald-950/40 text-emerald-300"
              : "border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.12)] text-[#ff8a8a]"
          }`}
        >
          {enrichMsg.text}
        </div>
      ) : null}

      {preview ? (
        <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-400">
          <span>
            <span className="font-semibold text-zinc-200">{preview.companies}</span>{" "}
            customer{preview.companies === 1 ? "" : "s"} ·{" "}
            <span className="font-semibold text-zinc-200">{preview.domainsTotal}</span>{" "}
            root domain{preview.domainsTotal === 1 ? "" : "s"} ready to scan
          </span>
          {preview.perCompany.length ? (
            <button
              type="button"
              onClick={() => setShowTargets((v) => !v)}
              className="text-[#ff4d57] transition hover:text-white"
            >
              {showTargets ? "Hide targets" : "Preview targets"}
            </button>
          ) : null}
        </div>
      ) : null}

      {preview && showTargets ? (
        <div className="mt-3 max-h-56 space-y-2 overflow-y-auto rounded-lg border border-zinc-900 bg-[#080808] p-3">
          {preview.perCompany.map((row) => (
            <div key={row.company} className="text-xs">
              <span className="font-medium text-zinc-200">{row.company}</span>
              <span className="ml-2 text-zinc-500">{row.domains.join(", ")}</span>
            </div>
          ))}
        </div>
      ) : null}

      {msg ? (
        <div
          className={`mt-4 rounded-lg border px-3 py-2 text-xs ${
            msg.ok
              ? "border-emerald-900/60 bg-emerald-950/40 text-emerald-300"
              : "border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.12)] text-[#ff8a8a]"
          }`}
        >
          {msg.text} Scans run in the background — use each engine&apos;s{" "}
          <strong>Sync now</strong> button to pull results once they finish.
        </div>
      ) : null}
    </div>
  );
}

// One-click "Sync all" — pull results from every configured connector.
function SyncAllButton() {
  const [busy, setBusy] = useState(false);
  const [rows, setRows] = useState<
    { connector: string; configured: boolean; ok: boolean; result?: any; error?: string }[] | null
  >(null);
  const [enrichSummary, setEnrichSummary] = useState<string | null>(null);

  async function run() {
    if (busy) return;
    setBusy(true);
    setRows(null);
    setEnrichSummary(null);
    try {
      const res = await fetch("/api/connectors/sync-all", { method: "POST" });
      const json = await res.json().catch(() => ({}));
      setRows(json.results ?? []);
      const e = json.enrich;
      if (e) {
        const parts = [];
        if (e.findingsUpdated) parts.push(`${e.findingsUpdated} re-scored`);
        if (e.kevAdded) parts.push(`${e.kevAdded} KEV`);
        if (e.ransomwareLinked) parts.push(`${e.ransomwareLinked} ransomware-linked`);
        if (e.cvesWithEpss) parts.push(`${e.cvesWithEpss} with EPSS`);
        if (parts.length) setEnrichSummary(`Threat intel: ${parts.join(" · ")}`);
      }
    } catch {
      setRows([{ connector: "Sync", configured: true, ok: false, error: "Request failed." }]);
    } finally {
      setBusy(false);
    }
  }

  const active = rows?.filter((r) => r.configured) ?? [];

  return (
    <div className="flex flex-col items-end gap-2">
      <button
        type="button"
        onClick={run}
        disabled={busy}
        className="inline-flex items-center gap-2 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-3.5 py-1.5 text-sm font-medium text-emerald-300 transition hover:bg-emerald-900/40 disabled:cursor-not-allowed disabled:opacity-40"
      >
        <RefreshCw size={14} className={busy ? "animate-spin" : ""} />
        {busy ? "Syncing all…" : "Sync all engines"}
      </button>
      {active.length ? (
        <div className="w-full max-w-md rounded-lg border border-zinc-900 bg-[#080808] p-2 text-xs">
          {active.map((r) => (
            <div key={r.connector} className="flex items-center justify-between gap-3 px-1 py-0.5">
              <span className="flex items-center gap-1.5 text-zinc-300">
                <span className={`h-1.5 w-1.5 rounded-full ${r.ok ? "bg-emerald-400" : "bg-[#ff4d57]"}`} />
                {r.connector}
              </span>
              <span className={r.ok ? "text-zinc-500" : "text-[#ff8a8a]"}>
                {r.ok ? summarizeSync(r.result?.result ?? r.result) : r.error ?? "failed"}
              </span>
            </div>
          ))}
          {enrichSummary ? (
            <div className="mt-1 border-t border-zinc-900 px-1 pt-1.5 text-emerald-400">
              {enrichSummary}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

const statusClass: Record<ConnectorStatus, string> = {
  Connected: "bg-emerald-950/60 text-emerald-300 border border-emerald-900/60",
  "Demo Mode": "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  "Not Configured": "bg-zinc-900 text-zinc-500 border border-zinc-800",
  "CSV Upload": "bg-[rgba(59,130,246,0.10)] text-sky-300 border border-sky-900/60",
  Planned: "bg-zinc-900 text-zinc-400 border border-zinc-800",
  Error: "bg-[rgba(179,14,20,0.16)] text-[#ff4d57] border border-[rgba(179,14,20,0.45)]",
};

function IntegrationCard({ card }: { card: CardData }) {
  const Icon = cardIcon[card.id] ?? IconRadar;
  const syncUrl = SYNC_ENDPOINTS[card.id];
  const healthUrl = HEALTH_ENDPOINTS[card.id];
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [progress, setProgress] = useState<TidalSyncStatus | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const isTidal = card.id === "tidal";
  // Offline upload fallback: Tidal takes a CSV inventory export, Burp takes an
  // XML issue export. Same flow, different endpoint/format.
  const uploadSpec =
    card.id === "tidal"
      ? {
          endpoint: "/api/tidal/import-file",
          accept: ".csv,text/csv",
          contentType: "text/csv",
          label: "CSV",
          eyebrow: "Offline import (fallback)",
          blurb:
            "Prefer live sync above (set TIDAL_EMAIL / TIDAL_PASSWORD). Or export your inventory to CSV from the Tidal portal and drop the file here to load assets, owners, and business criticality.",
        }
      : card.id === "burp"
        ? {
            endpoint: "/api/burp/import-file",
            accept: ".xml,text/xml,application/xml",
            contentType: "application/xml",
            label: "XML",
            eyebrow: "Offline import (Burp Professional)",
            blurb:
              "Prefer live sync above (set BURP_API_URL / BURP_API_KEY for Burp Suite Enterprise). Or export issues as XML from Burp Suite Professional and drop the file here to load validated web findings.",
          }
        : card.id === "nmap"
          ? {
              endpoint: "/api/nmap/import-file",
              accept: ".xml,text/xml,application/xml",
              contentType: "application/xml",
              label: "XML",
              eyebrow: "Offline import (nmap -oX)",
              blurb:
                "Prefer live sync above (set NMAP_RUNNER_URL / NMAP_RUNNER_TOKEN). Or run nmap with -oX and drop the XML output here to attach open-port facts to assets and raise exposed-service findings.",
            }
          : null;
  const supportsCsv = uploadSpec !== null;
  const [health, setHealth] = useState<
    { reachable: boolean; message: string } | null | undefined
  >(healthUrl && card.configured ? undefined : null);

  useEffect(() => {
    if (!healthUrl || !card.configured) return;
    let alive = true;
    void fetch(healthUrl, { cache: "no-store" })
      .then((r) => r.json())
      .then((j) => {
        if (alive) setHealth({ reachable: Boolean(j.reachable), message: j.message ?? "" });
      })
      .catch(() => {
        if (alive) setHealth({ reachable: false, message: "unreachable" });
      });
    return () => {
      alive = false;
    };
  }, [healthUrl, card.configured]);

  async function runSync() {
    if (!syncUrl || syncing) return;
    setSyncing(true);
    setSyncMsg(null);
    setProgress(null);
    try {
      const res = await fetch(syncUrl, { method: "POST" });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || json.error) {
        setSyncMsg({ ok: false, text: json.error ?? `Sync failed (HTTP ${res.status})` });
        setSyncing(false);
        return;
      }
      if (isTidal) {
        // Background job — poll for progress until it finishes.
        setProgress(json.status ?? null);
        await pollTidal();
      } else {
        setSyncMsg({ ok: true, text: summarizeSync(json.result ?? json) });
        setSyncing(false);
      }
    } catch (err) {
      setSyncMsg({ ok: false, text: err instanceof Error ? err.message : "Sync failed." });
      setSyncing(false);
    }
  }

  async function pollTidal() {
    for (let i = 0; i < 3000; i += 1) {
      await new Promise((r) => setTimeout(r, 1200));
      let st: TidalSyncStatus | null = null;
      try {
        const r = await fetch(syncUrl, { method: "GET", cache: "no-store" });
        const j = await r.json().catch(() => ({}));
        st = j.status ?? null;
      } catch {
        continue; // transient — keep polling
      }
      if (!st) break;
      setProgress(st);
      if (!st.running) {
        if (st.error) setSyncMsg({ ok: false, text: st.error });
        else if (st.result) setSyncMsg({ ok: true, text: summarizeSync(st.result) });
        break;
      }
    }
    setSyncing(false);
  }

  async function uploadCsv(file: File) {
    if (uploading || !uploadSpec) return;
    setUploading(true);
    setSyncMsg(null);
    try {
      const text = await file.text();
      const res = await fetch(uploadSpec.endpoint, {
        method: "POST",
        headers: { "Content-Type": uploadSpec.contentType },
        body: text,
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || json.error) {
        setSyncMsg({ ok: false, text: json.error ?? `Import failed (HTTP ${res.status})` });
      } else {
        setSyncMsg({ ok: true, text: summarizeSync(json.result ?? json) });
      }
    } catch (err) {
      setSyncMsg({
        ok: false,
        text: err instanceof Error ? err.message : "Import failed.",
      });
    } finally {
      setUploading(false);
    }
  }

  return (
    <PanelCard
      eyebrow={card.vendor}
      actions={<Pill className={statusClass[card.status]}>{card.status}</Pill>}
    >
      <div className="flex items-start gap-4">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.08)] text-[#b30e14]">
          <Icon size={26} />
        </div>
        <div className="min-w-0">
          <h2 className="text-xl font-semibold text-white">{card.name}</h2>
          <div className="mt-1 text-sm text-zinc-500">{card.kind}</div>
          <p className="mt-3 text-sm leading-relaxed text-zinc-400">
            {card.description}
          </p>
        </div>
      </div>

      <div className="mt-5 flex flex-wrap gap-2">
        {card.capabilities.map((cap) => (
          <span
            key={cap}
            className="rounded-full border border-zinc-800 bg-zinc-950 px-3 py-1 text-xs text-zinc-300"
          >
            {cap}
          </span>
        ))}
      </div>

      <div className="mt-5 rounded-2xl border border-zinc-900 bg-[#090909] p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="text-xs uppercase tracking-[0.24em] text-zinc-500">
            Configuration
          </div>
          {healthUrl && card.configured ? (
            <span
              title={health?.message ?? "Checking reachability…"}
              className={`inline-flex items-center gap-1.5 text-xs ${
                health === undefined
                  ? "text-zinc-500"
                  : health?.reachable
                    ? "text-emerald-300"
                    : "text-[#ff8a8a]"
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  health === undefined
                    ? "animate-pulse bg-zinc-600"
                    : health?.reachable
                      ? "bg-emerald-400"
                      : "bg-[#ff4d57]"
                }`}
              />
              {health === undefined
                ? "Checking…"
                : health?.reachable
                  ? "Live"
                  : "Unreachable"}
            </span>
          ) : null}
        </div>
        <div className="mt-3 space-y-2">
          {card.envVars.map((envVar) => (
            <div key={envVar} className="flex items-center justify-between gap-4">
              <code className="text-sm text-zinc-300">{envVar}</code>
              <span
                className={
                  card.configured
                    ? "text-xs text-emerald-300"
                    : "text-xs text-zinc-500"
                }
              >
                {card.configured ? "set" : "not set"}
              </span>
            </div>
          ))}
        </div>
      </div>

      {supportsCsv ? (
        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            const file = e.dataTransfer.files?.[0];
            if (file) void uploadCsv(file);
          }}
          className="mt-4 rounded-2xl border border-dashed border-zinc-800 bg-[#090909] p-4 text-center"
        >
          <input
            ref={fileInputRef}
            type="file"
            accept={uploadSpec?.accept}
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void uploadCsv(file);
              e.target.value = "";
            }}
          />
          <div className="text-xs uppercase tracking-[0.24em] text-zinc-500">
            {uploadSpec?.eyebrow}
          </div>
          <p className="mt-2 text-sm text-zinc-400">{uploadSpec?.blurb}</p>
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="mt-3 inline-flex items-center gap-2 rounded-lg border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.12)] px-3 py-1.5 text-sm font-medium text-[#ff4d57] transition hover:bg-[rgba(179,14,20,0.2)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Upload size={14} className={uploading ? "animate-pulse" : ""} />
            {uploading ? "Importing…" : `Choose ${uploadSpec?.label} file`}
          </button>
        </div>
      ) : null}

      <div className="mt-4 flex items-center justify-between gap-3">
        <a
          href={card.docsUrl}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-2 text-sm text-[#ff4d57] transition hover:text-white"
        >
          <ExternalLink size={14} />
          Documentation
        </a>
        {syncUrl ? (
          <button
            type="button"
            onClick={runSync}
            disabled={syncing || !card.configured}
            title={
              card.configured
                ? "Pull the latest scan results into the console"
                : "Set this connector's environment variables to enable sync"
            }
            className="inline-flex items-center gap-2 rounded-lg border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.12)] px-3 py-1.5 text-sm font-medium text-[#ff4d57] transition hover:bg-[rgba(179,14,20,0.2)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            <RefreshCw size={14} className={syncing ? "animate-spin" : ""} />
            {syncing ? "Syncing…" : "Sync now"}
          </button>
        ) : null}
      </div>

      {isTidal && syncing && progress ? (
        <div className="mt-3 rounded-lg border border-zinc-800 bg-[#090909] px-3 py-3">
          <div className="flex items-center justify-between text-xs text-zinc-300">
            <span className="truncate">
              {progress.phase}
              {progress.currentCompany ? "" : "…"}
            </span>
            <span className="tabular-nums text-zinc-500">
              {progress.companiesTotal
                ? `${progress.companiesDone}/${progress.companiesTotal}`
                : ""}
            </span>
          </div>
          <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-zinc-800">
            <div
              className="h-full rounded-full bg-[#ff4d57] transition-all duration-500"
              style={{
                width: progress.companiesTotal
                  ? `${Math.round((progress.companiesDone / progress.companiesTotal) * 100)}%`
                  : "8%",
              }}
            />
          </div>
          <div className="mt-2 flex items-center justify-between text-[11px] text-zinc-500">
            <span className="truncate">{progress.currentCompany || " "}</span>
            <span className="tabular-nums">{progress.assetsFound} assets</span>
          </div>
        </div>
      ) : null}

      {syncMsg ? (
        <div
          className={`mt-3 rounded-lg border px-3 py-2 text-xs ${
            syncMsg.ok
              ? "border-emerald-900/60 bg-emerald-950/40 text-emerald-300"
              : "border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.12)] text-[#ff8a8a]"
          }`}
        >
          {syncMsg.text}
        </div>
      ) : null}
    </PanelCard>
  );
}

export default function VulnConnectorsPage() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [integrations, setIntegrations] = useState<CardData[]>([]);

  useEffect(() => {
    void fetch("/api/connectors", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setConnectors(json.connectors ?? []))
      .catch(() => undefined);
    void fetch("/api/integrations", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setIntegrations(json.integrations ?? []))
      .catch(() => undefined);
  }, []);

  return (
    <VulnShell
      eyebrow="Connectors"
      title="Connectors & integrations"
      subtitle="Scan engines, telemetry sources, and asset inventory feeding the console. Each integration runs in demo mode until its credentials are set in the environment."
    >
      <OsintLaunchBanner />

      <div className="flex items-start justify-between gap-4">
        <div className="text-[13px] uppercase tracking-[0.3em] text-[#b30e14]">
          Scanners
        </div>
        <SyncAllButton />
      </div>
      <div className="grid gap-5 xl:grid-cols-2">
        {connectors.map((connector) => (
          <IntegrationCard key={connector.id} card={connector as CardData} />
        ))}
      </div>

      <div className="mt-2 text-[13px] uppercase tracking-[0.3em] text-[#b30e14]">
        Asset inventory
      </div>
      <div className="grid gap-5 xl:grid-cols-2">
        {integrations.map((integration) => (
          <IntegrationCard key={integration.id} card={integration} />
        ))}
      </div>
    </VulnShell>
  );
}
