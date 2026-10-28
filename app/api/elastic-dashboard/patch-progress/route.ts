import {dashboardAccess,dashboardJson,dashboardFailure} from '@/lib/elastic-dashboard-http';
import {DashboardError} from '@/lib/elastic-dashboard';
import {applicationDatabase} from '@/lib/persist';
import {readPatchProgress} from '@/lib/patch-progress-store';
export const dynamic='force-dynamic';
export async function GET(request:Request){
  try{
    await dashboardAccess();
    const params=new URL(request.url).searchParams,companyId=params.get('companyId')||'',requestId=params.get('requestId')||undefined,kind=params.get('kind')||undefined;
    if(!/^[A-Za-z0-9_-]{1,100}$/.test(companyId))throw new DashboardError('Select a customer.',400);
    if(requestId&&(!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(requestId)||!['single','group'].includes(kind||'')))throw new DashboardError('Invalid patch request.',400);
    const offset=Number(params.get('offset')||0);if(!Number.isInteger(offset)||offset<0||offset>100000)throw new DashboardError('Invalid page.',400);
    const db=applicationDatabase();if(!db)throw new DashboardError('Progress storage is unavailable.',503);
    return dashboardJson(await readPatchProgress(db,companyId,{offset,requestId,kind,detailOffset:offset}));
  }catch(error){return dashboardFailure(error);}
}
