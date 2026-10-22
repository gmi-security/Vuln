export default function PrioritizeLayoutPreview() {
  return <section id="prioritize-layout-preview" aria-label="Proposed Prioritize layout preview"
    className="rounded-2xl border border-dashed border-amber-700/70 bg-[#090909] p-5 sm:p-7">
    <div className="mb-4">
      <p className="text-xs uppercase tracking-widest text-amber-200">Design preview · Sample data</p>
      <h2 className="mt-2 text-2xl font-semibold text-white">Proposed Prioritize layout</h2>
      <p className="mt-2 text-sm text-zinc-300">Try the simplified worklist and review flow below. This preview uses example customers and simulated tickets; it does not change your selected customer or create real tickets. The existing sections above are unchanged.</p>
    </div>
    <iframe title="Interactive Prioritize layout preview — sample data only"
      src="/previews/prioritize-layout.html" sandbox="allow-scripts" referrerPolicy="no-referrer" loading="lazy"
      className="h-[1100px] w-full rounded-xl border border-zinc-800 bg-[#090a0c]" />
  </section>;
}
