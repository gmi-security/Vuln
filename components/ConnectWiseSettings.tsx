"use client";
import { useEffect, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import { ConnectWiseRouting, type CWSettings } from "@/components/ConnectWiseFields";
import type { CWDefaults } from "@/lib/connectwise-client";
import { inputClass, selectClass } from "@/components/ui";
import styles from "./QueryDashboard.module.css";

export default function ConnectWiseSettings() {
  const [settings, setSettings] = useState<CWSettings>({ configured: false, defaults: {} });
  const [form, setForm] = useState({ endpoint: "", companyId: "", clientId: "", publicKey: "", privateKey: "", cwAuth: "", authMode: "encoded" });
  const [defaults, setDefaults] = useState<CWDefaults>({}), [busy, setBusy] = useState("loading"), [error, setError] = useState(""), [message, setMessage] = useState("");
  useEffect(() => {
    let live = true;
    dashboardRequest<CWSettings>("connectwise").then(data => { if (live) {
      setSettings(data); setDefaults(data.defaults); setForm(old => ({ ...old, endpoint: data.endpoint ?? "", companyId: data.companyId ?? "", clientId: data.clientId ?? "", authMode: data.authMode ?? (data.configured ? "separate" : "encoded") }));
      if (data.error) setError(data.error);
    } }).catch(e => { if (live) setError(e.message); }).finally(() => { if (live) setBusy(""); });
    return () => { live = false; };
  }, []);
  async function save(path: string, value: unknown) {
    setBusy(path); setError(""); setMessage("");
    try {
      const data = await dashboardRequest<CWSettings>(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(value) });
      setSettings(data); setDefaults(data.defaults); setForm(old => ({ ...old, companyId: data.companyId ?? old.companyId, publicKey: "", privateKey: "", cwAuth: "" }));
      setMessage(path.endsWith("defaults") ? "Routing defaults saved. Select the customer when creating each ticket." : "ConnectWise connection verified and saved. The lists below use your actual ConnectWise names.");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not save ConnectWise settings."); } finally { setBusy(""); }
  }
  return <div className="space-y-6">
    <form className="space-y-4" onSubmit={e => { e.preventDefault(); void save("connectwise", form.authMode === "encoded" ? { endpoint: form.endpoint, clientId: form.clientId, authMode: form.authMode, cwAuth: form.cwAuth } : { endpoint: form.endpoint, clientId: form.clientId, companyId: form.companyId, publicKey: form.publicKey, privateKey: form.privateKey }); }}>
      <fieldset disabled={Boolean(busy)} className="grid gap-4 sm:grid-cols-2">
        <label className="block text-sm text-zinc-200 sm:col-span-2">ConnectWise PSA API address
          <input type="url" required className={`${inputClass} mt-2`} value={form.endpoint} onChange={e => setForm({ ...form, endpoint: e.target.value })} placeholder="https://api-na.myconnectwise.net/v4_6_release/apis/3.0" autoComplete="off" />
        </label>
        <label className="block text-sm text-zinc-200 sm:col-span-2">Authentication method<select aria-label="Authentication method" className={`${selectClass} mt-2 block w-full`} value={form.authMode} onChange={e => setForm({ ...form, authMode: e.target.value, cwAuth: "", publicKey: "", privateKey: "" })}><option value="encoded">CW_AUTH (encoded authorization)</option><option value="separate">Company ID and separate API keys</option></select></label>
        {form.authMode === "separate" && <label className="block text-sm text-zinc-200">Login company ID<input required className={`${inputClass} mt-2`} value={form.companyId} onChange={e => setForm({ ...form, companyId: e.target.value })} autoComplete="off" spellCheck={false} /></label>}
        <label className="block text-sm text-zinc-200">ConnectWise Client ID<input required className={`${inputClass} mt-2`} value={form.clientId} onChange={e => setForm({ ...form, clientId: e.target.value })} autoComplete="off" spellCheck={false} /></label>
        {form.authMode === "encoded" ? <label className="block text-sm text-zinc-200 sm:col-span-2">CW_AUTH<input aria-label="CW_AUTH" type="password" required={!settings.configured} maxLength={20000} className={`${inputClass} mt-2`} value={form.cwAuth} onChange={e => setForm({ ...form, cwAuth: e.target.value })} autoComplete="new-password" spellCheck={false} placeholder={settings.configured ? "Saved securely — leave blank to keep" : "Paste the encoded CW_AUTH value"} /><span className={`${styles.resultNote} block`}>Paste only the value after CW_AUTH=. A Basic prefix is also accepted. Your login company ID and API keys are read from this value on the server.</span></label> : <>
        <label className="block text-sm text-zinc-200">Public API key<input type="password" required={!settings.configured} className={`${inputClass} mt-2`} value={form.publicKey} onChange={e => setForm({ ...form, publicKey: e.target.value })} autoComplete="new-password" spellCheck={false} placeholder={settings.configured ? "Saved securely — leave blank to keep" : "Paste public key"} /></label>
        <label className="block text-sm text-zinc-200">Private API key<input type="password" required={!settings.configured} className={`${inputClass} mt-2`} value={form.privateKey} onChange={e => setForm({ ...form, privateKey: e.target.value })} autoComplete="new-password" spellCheck={false} placeholder={settings.configured ? "Saved securely — leave blank to keep" : "Paste private key"} /></label>
        </>}
        <p className={`${styles.resultNote} sm:col-span-2`}>Credentials are encrypted on the server and never returned to the browser. Use an API member with permission to read companies, boards, statuses, teams and priorities, create service tickets, and read/upload ticket documents. The ticket's customer is chosen separately.</p>
        <button type="submit" className={`${styles.primaryButton} justify-self-start`}>{busy === "connectwise" ? "Testing and saving…" : "Test and save ConnectWise"}</button>
      </fieldset>
    </form>
    {settings.configured && <form className="space-y-4 border-t border-zinc-800 pt-5" onSubmit={e => { e.preventDefault(); void save("connectwise/defaults", defaults); }}>
      <h3 className="text-lg text-zinc-100">Default patch ticket routing</h3>
      <ConnectWiseRouting value={defaults} onChange={setDefaults} revision={settings.revision} disabled={Boolean(busy)} />
      <button type="submit" className={styles.button} disabled={Boolean(busy)}>{busy.endsWith("defaults") ? "Saving defaults…" : "Save routing defaults"}</button>
    </form>}
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    {message && <p role="status" className={styles.resultNote}>{message}</p>}
  </div>;
}
