export const company={id:'CO-REPORT',name:'Synthetic customer'};
export function reportingFixture(n=800){
 const connectors=['nessus','vulners','crowdstrike','defender','qualys','spiderfoot','artemis','burp','zap','nmap'];
 const statuses=['Open','In Remediation','Resolved','False Positive','Risk Accepted'];
 const severity=['Critical','High','Medium','Low','Info'];
 const findings=Array.from({length:n},(_,i)=>({id:`F-${i}`,companyId:company.id,connector:connectors[i%10],
  status:statuses[Math.floor(i/10)%5],severity:severity[Math.floor(i/50)%5],cve:i%9?'CVE-2026-1234':'EXPOSURE-1',
  realRisk:i%11,cvss:i%10,title:`Finding ${i}`,asset:`host-${i%30}`,lastSeen:`2026-10-${String(i%9+1).padStart(2,'0')}T01:00:00Z`,
  kev:i%3===0,exploitAvailable:i%4===0,assetSource:i%3===0?'tidal':i%3===1?'manual':'inferred',
  ...(i%7===0?{seenBy:['nessus','crowdstrike','nessus']}:{}),
  ...(i%13===0?{enrichments:[{source:'vulners',observedAt:'2026-10-10T01:00:00Z'}]}:{})}));
 const scans=Array.from({length:40},(_,i)=>({id:`S-${i}`,companyId:company.id,name:`Scan ${i}`,connector:connectors[i%10],
  status:['Completed','Failed','Running','Queued','Paused','Stopped'][i%6],createdAt:`2026-10-0${i%9+1}T00:00:00Z`,
  completedAt:i%6===0?'2026-10-10T00:00:00Z':null,findingsCount:i,hostsScanned:i+1}));
 const assets=Array.from({length:40},(_,i)=>({id:`A-${i}`,companyId:company.id,identifier:`host-${39-i}`,
  source:['tidal','manual','inferred','defender','intune'][i%5],lastSynced:'2026-10-09T00:00:00Z'}));
 const history=[{ts:'2026-10-09T00:00:00Z',data:{totalOpen:101}},{ts:'2026-10-10T00:00:00Z',data:{different:3}}];
 return {findings,scans,assets,history};
}
export function expectedReport(reference,data,owner=company){
 return reference(owner,[...data.findings].sort((a,b)=>b.realRisk-a.realRisk||b.cvss-a.cvss),
  [...data.scans].sort((a,b)=>b.createdAt>a.createdAt?1:-1),
  [...data.assets].sort((a,b)=>a.identifier.localeCompare(b.identifier)),data.history);
}
