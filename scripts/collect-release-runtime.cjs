// Read-only process inspection plus a private recovery copy. Does not restart
// anything, change PM2 configuration, load the app or contact any provider.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
if(process.platform!=='linux'||process.getuid()!==0)throw Error('Run from the root terminal on the Vuln server');
const parent='/root/vuln-release-recovery';fs.mkdirSync(parent,{recursive:true,mode:0o700});fs.chmodSync(parent,0o700);
const backup=fs.mkdtempSync(path.join(parent,'runtime-'));fs.chmodSync(backup,0o700);
const processes=[],managers=[];
const homes=['/root',...fs.readdirSync('/home',{withFileTypes:true}).filter(e=>e.isDirectory()).map(e=>path.join('/home',e.name))];
for(const home of homes){
 const pm2Home=path.join(home,'.pm2'),pidFile=path.join(pm2Home,'pm2.pid');if(!fs.existsSync(pidFile))continue;
 const daemon=Number(fs.readFileSync(pidFile,'utf8').trim());if(!Number.isSafeInteger(daemon)||daemon<=0)continue;
 try{process.kill(daemon,0);}catch{continue;} // Check only; never starts a daemon.
 if(!fs.existsSync(path.join(pm2Home,'rpc.sock')))continue;
 const raw=cp.execFileSync('/usr/bin/pm2',['jlist'],{encoding:'utf8',timeout:15000,maxBuffer:8*1024*1024,env:{...process.env,PM2_HOME:pm2Home}});
 const rows=JSON.parse(raw);if(!Array.isArray(rows))throw Error('Unexpected PM2 output');
 const owner=path.basename(home),selected=rows.filter(p=>/vuln/i.test(p.name??'')||/\/opt\/vuln(?:\/|$)/.test(p.pm2_env?.pm_cwd??''));
 managers.push({owner,processes:rows.length,vulnProcesses:selected.length});
 fs.writeFileSync(path.join(backup,owner+'-vuln-pm2-private.json'),JSON.stringify(selected),{mode:0o600,flag:'wx'});
 processes.push(...selected.map(p=>({...p,managerOwner:owner})));
}
if(!processes.length)throw Error('No existing Vuln PM2 processes found');
const flags=['VULN_DISABLE_SCHEDULER','VULN_REMEDIATION_UI','VULN_PLATFORM_STORE','VULN_REPORTING_INPUT_REVISIONS',
 'VULN_REPORTING_SQL_READS','VULN_REPORTING_WORKER_ENABLED','VULN_REPORTING_EXECUTIVE_ENABLED',
 'VULN_SAVED_SOURCE_READS','VULN_SHADOW_CVE_READS','SCANNER_ELASTIC_EXPORT_ENABLED','VULNERS_BRIDGE_SCHEDULER_ENABLED'];
const result={collectedAt:new Date().toISOString(),privateBackup:backup,managers,processes:processes.map(p=>{
 const e=p.pm2_env??{};let initial={},environmentReadable=false;
 try{for(const pair of fs.readFileSync(`/proc/${Number(p.pid)}/environ`,'utf8').split('\0')){
  const i=pair.indexOf('=');if(i>0)initial[pair.slice(0,i)]=pair.slice(i+1);
 }environmentReadable=true;}catch{}
 return {owner:p.managerOwner,id:p.pm_id,name:p.name,pid:p.pid,status:e.status,cwd:e.pm_cwd,executable:e.pm_exec_path,
  instances:e.instances,mode:e.exec_mode,restarts:e.restart_time,environmentReadable,
  startupFlags:Object.fromEntries(flags.map(k=>[k,['true','false','sql','legacy'].includes(initial[k])?initial[k]:initial[k]===undefined?'unset':'other'])),
  nodeHeapMiB:((initial.NODE_OPTIONS??'')+' '+(Array.isArray(e.node_args)?e.node_args.join(' '):'')).match(/--max-old-space-size(?:=|\s+)(\d+)/)?.[1]??null,
  killTimeoutMs:e.kill_timeout??null,memoryRestartBytes:e.max_memory_restart??null};
 }),limitations:['Startup environment only; the app also loads its environment files.','External cron, remote orchestration and in-flight jobs require maintenance review.']};
console.log(JSON.stringify(result,null,2));
