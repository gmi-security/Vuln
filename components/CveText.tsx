"use client";

export function cveIdentifier(value: unknown): string | undefined {
  return typeof value === "string" && /^CVE-\d{4}-\d{4,19}$/i.test(value.trim()) ? value.trim().toUpperCase() : undefined;
}

export default function CveText({ text, onSelect }: { text: string; onSelect?: (cve: string) => void }) {
  if (!onSelect) return <>{text}</>;
  return <>{text.split(/(\bCVE-\d{4}-\d{4,19}\b)/gi).map((part, index) => {
    const cve = cveIdentifier(part);
    return cve ? <button key={index} type="button" className="cursor-pointer text-sky-300 underline decoration-sky-300/40 underline-offset-4 hover:text-sky-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-300" onClick={() => onSelect(cve)} aria-label={`View ${cve} details`}>{part}</button> : part;
  })}</>;
}
