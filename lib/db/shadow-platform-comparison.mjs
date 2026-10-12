// Read-only publication comparison; no initializer, hydration or source API.
import {shadowReadRequest} from './defender-shadow-reads.mjs';
import {readPublishedDefenderShadow} from './defender-shadow-publication.mjs';
const fail=(message,status=400)=>{throw Object.assign(new Error(message),{status});};
export function shadowPlatformRequest(raw){
  if(!raw||Object.keys(raw).some(key=>!['companyId','view','status','limit','cursor'].includes(key)))fail('Unsupported comparison parameters');
  const {companyId,view='summary',status='open',limit='50',cursor=null}=raw;
  if(typeof companyId!=='string'||!/^CO-[A-Za-z0-9-]{1,98}$/.test(companyId)||
    !['summary','findings','cves'].includes(view)||!['open','all','Open','In Remediation','Risk Accepted','False Positive','Resolved'].includes(status)||
    (view!=='findings'&&status!=='open')||typeof limit!=='string'||!/^([1-9][0-9]?|100)$/.test(limit))fail('Invalid comparison customer, view, status or page size');
  if(cursor!==null){
    if(view==='summary'||typeof cursor!=='string'||cursor.length>1024||!/^[A-Za-z0-9_-]+$/.test(cursor))fail('Invalid comparison cursor');
    try{
      const decoded=JSON.parse(Buffer.from(cursor,'base64url').toString('utf8'));
      // Validate cursor shape, customer, view and workflow scope before opening
      // storage. Its generation is never used to choose what data to read.
      shadowReadRequest({companyId,view,status,limit:Number(limit),cursor,projectionId:decoded.p});
    }catch{fail('Invalid comparison cursor scope');}
  }
  return {companyId,view,status,limit:Number(limit),cursor};
}
export async function readShadowPlatformComparison(client,request){
  try{return await readPublishedDefenderShadow(client,request);}
  catch(error){
    if(error.message==='Page cursor scope or position mismatch')fail('Published comparison changed. Restart from the first page.',409);
    throw error;
  }
}
