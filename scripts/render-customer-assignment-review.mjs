// Local, standalone review artifact. No database, browser storage or network use.
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--input' || args[2] !== '--output')
  throw new Error('Use --input PRIVATE_REVIEW_JSON --output NEW_PRIVATE_HTML');
const report = JSON.parse(await readFile(resolve(args[1]), 'utf8'));
if (report.mode !== 'proposed-assignment-review' || !Array.isArray(report.companies))
  throw new Error('Expected a customer assignment review collector output.');
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const number = value => Number(value || 0).toLocaleString('en-US');
const label = provider => ({crowdstrike:'CrowdStrike',defender:'Defender',nessus:'Nessus',spiderfoot:'SpiderFoot',
  artemis:'Artemis',zap:'ZAP',vulners:'Vulners',automate:'Automate',tidal:'Tidal',elastic:'Elasticsearch'}[provider] ?? provider);
const badge = (value, cls='') => `<span class="badge ${cls}">${escape(value)}</span>`;
const list = values => values.length ? `<ul>${values.map(v => `<li>${escape(v)}</li>`).join('')}</ul>` : '<p class="muted">None recorded.</p>';
const companies = [...report.companies].sort((a,b) => a.name.localeCompare(b.name));
const rows = companies.map(company => {
  const evidence = [company.savedDefenderConnection && 'Saved Defender connection',
    company.completedSpotlightPointer && 'Completed Spotlight import',
    ...company.savedTiles.map(t => `Saved ${label(t.source)} tile`)].filter(Boolean);
  const providers = [...new Set(company.scanners.map(s=>s.provider))].sort();
  const scans = company.scanners.reduce((total,s)=>total+s.scans,0);
  const details = company.scanners.map(s => `<section><h4>${escape(label(s.provider))}</h4>
    <p>${number(s.scans)} recorded scans/imports; ${number(s.completed)} marked completed. ${number(s.targets.length)} distinct recorded targets.</p>
    ${s.targets.length ? `<details><summary>Recorded targets (historical scope)</summary>${list(s.targets)}</details>` : ''}
    ${s.references.length ? `<details><summary>External references</summary>${list(s.references)}</details>` : ''}</section>`).join('');
  return `<article data-search="${escape([company.id,company.name,...providers,...company.inventory.map(i=>i.source)].join(' ').toLowerCase())}">
    <div class="customer"><h3>${escape(company.name)}</h3><span class="muted">${escape(company.id)}</span></div>
    <div class="evidence">${evidence.length ? evidence.map(e=>badge(e,'explicit')).join('') : '<span class="muted">No explicit connection/tile owner in this collection.</span>'}</div>
    <div class="history">${providers.map(p=>badge(label(p))).join('') || '<span class="muted">No scan/import records.</span>'}
      <p class="muted">${number(scans)} recorded scans/imports</p></div>
    <details class="detail"><summary>Review evidence</summary>
      <p class="notice">This is evidence for review, not an active assignment. Historical scans and inventory do not establish current tenant permission or vulnerability coverage.</p>
      <h4>Inventory by recorded source</h4>${list(company.inventory.map(i=>`${label(i.source ?? 'Unspecified')}: ${number(i.count)} assets`))}
      ${details || '<p>No scanner scope was found in this collection.</p>'}
      <h4>Explicitly owned saved tiles</h4>${list(company.savedTiles.map(t=>`${label(t.source)}: ${t.id}`))}
    </details></article>`;
}).join('');
const explicit = companies.filter(c=>c.savedDefenderConnection||c.completedSpotlightPointer||c.savedTiles.length).length;
const scanCount = companies.reduce((sum,c)=>sum+c.scanners.reduce((n,s)=>n+s.scans,0),0);
const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'">
<title>GMI Vuln — Customer connector review</title><style>
:root{font-family:system-ui,Segoe UI,sans-serif;color:#193047;background:#edf2f7;font-size:16px;line-height:1.5}
*{box-sizing:border-box}body{margin:0}main{max-width:1300px;margin:auto;padding:32px 24px}h1{font-size:2rem;line-height:1.2;margin:.3em 0}h2{font-size:1.3rem}h3{font-size:1rem;margin:0}h4{margin:12px 0 4px}p{margin:6px 0 12px}.eyebrow{font-weight:700;letter-spacing:.1em;color:#326080}.muted{color:#526476;font-size:.875rem}.notice{background:#fff5d9;border-left:4px solid #aa6a00;padding:14px 18px;border-radius:4px}.stats{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0}.stat{background:white;border:1px solid #d4dde6;border-radius:9px;padding:16px 22px;flex:1;min-width:160px}.stat strong{display:block;font-size:1.7rem}.toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:20px 0}input{flex:1;min-width:220px;padding:12px;border:1px solid #899bab;border-radius:6px;font:inherit}button{font:inherit;background:#173f5f;color:white;border:0;border-radius:6px;padding:12px 18px;cursor:pointer}button:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid #00a2bc;outline-offset:3px}.headers,article{display:grid;grid-template-columns:1.1fr 1.2fr 1.35fr;gap:18px}.headers{padding:10px 18px;font-weight:650}article{background:white;border:1px solid #d4dde6;border-radius:8px;padding:18px;margin-bottom:10px;break-inside:avoid}article[hidden]{display:none}.badge{display:inline-block;margin:0 4px 5px 0;padding:3px 8px;border-radius:5px;background:#edf2f7;color:#2d4b64;font-size:.8rem}.explicit{background:#e1f1f6;color:#175567}.detail{grid-column:1/-1;border-top:1px solid #e0e7ee;padding-top:9px}summary{cursor:pointer;font-weight:600;color:#195778;padding:4px 0}section{padding:8px 0;border-bottom:1px solid #e0e7ee}ul{padding-left:22px;overflow-wrap:anywhere}footer{font-size:.875rem;color:#526476;margin-top:26px}#unassigned{background:white;border:1px solid #d4dde6;border-radius:8px;padding:18px;margin-top:24px}
@media(max-width:720px){main{padding:20px 14px}.headers{display:none}article{grid-template-columns:1fr;gap:10px}.detail{grid-column:1}.evidence:before{content:'Saved ownership evidence';display:block;font-size:.8rem;font-weight:650;margin-bottom:5px}.history:before{content:'Recorded source activity';display:block;font-size:.8rem;font-weight:650;margin-bottom:5px}}
@media print{body{background:white}main{padding:0}.toolbar{display:none}article{border-radius:0}.notice{background:white}details:not([open])>.notice{display:none}.stats{margin:12px 0}.stat{padding:8px}h1{font-size:1.5rem}}
</style></head><body><main><div class="eyebrow">VULN2.0 RELEASE REVIEW</div><h1>Customer connector assignments</h1>
<p>Read-only evidence collected ${escape(report.collectedAt)}. This file contains private customer scope information. It stays on your computer and makes no network requests.</p>
<p class="notice"><strong>No configuration has changed.</strong> Confirm the customer and tenant behind each connection, the permitted dataset/repository/targets, and which source is authoritative when sources overlap. Existing tiles and data are preserved. A blank evidence cell means this collector found no explicit owner, not that the customer has no data.</p>
<div class="stats"><div class="stat"><strong>${number(companies.length)}</strong>customers</div><div class="stat"><strong>${number(explicit)}</strong>with explicit saved ownership evidence</div><div class="stat"><strong>${number(scanCount)}</strong>recorded scans/imports</div><div class="stat"><strong>${number(report.unassignedTiles.length)}</strong>tiles without a saved owner</div></div>
<div class="toolbar"><label for="search">Find customer/source</label><input id="search" type="search" placeholder="Name, customer ID or connector"><button id="print" type="button">Print / save PDF</button></div>
<p id="count" class="muted" aria-live="polite">${companies.length} customers shown</p><div class="headers"><span>Customer</span><span>Saved ownership evidence</span><span>Recorded source activity</span></div>${rows}
<div id="unassigned"><h2>Saved tiles needing an owner review</h2><p>Do not delete or silently reassign these tiles. Confirm their existing dataset/customer scope before binding them.</p>${list(report.unassignedTiles.map(t=>`${label(t.source)}: ${t.id}`))}</div>
<footer><h2>Coverage and limitations</h2>${list(report.limitations)}<p>Environment-only connections and AppSec repository ownership are reviewed separately in the connector preview. This report does not contain API keys, passwords or database URLs. It is not an activation file.</p></footer>
</main><script>const cards=[...document.querySelectorAll('article')];document.querySelector('#search').addEventListener('input',e=>{const term=e.target.value.trim().toLowerCase();let visible=0;for(const card of cards){card.hidden=!card.dataset.search.includes(term);if(!card.hidden)visible++;}document.querySelector('#count').textContent=visible+' customers shown';});document.querySelector('#print').addEventListener('click',()=>window.print());</script></body></html>`;
await writeFile(resolve(args[3]),html,{flag:'wx',mode:0o600});
console.log(`Created private review: ${companies.length} customers, ${scanCount} scans/imports, no network requests.`);
