const deny=message=>{throw Error(message);};
const rootPattern=/^\/home\/codex\/vuln-recovery\/gate3-4-[a-z0-9]{6,32}$/;
const databasePattern=/^gate34_(?:repeat|fault(?:_(?:before|companies|scans|findings|assets|tickets|commit))?|restore|authority|app)_[a-z0-9]{6,32}$/;
export const precommitBackup={path:'/home/codex/vuln-recovery/gate3-precommit-ZSHf45/precommit.dump',
 sha256:'e8a52f902c834f8485ccdb6e2622e9355944d17596d569164d6c7b71512e1a23'};
export const verifiedManifestSha256='58825c0cea227b5b874a6fa9f1d3a02d3c288b3194cfd824ef837480f621a0ae';
export const verifiedPlanHash='cf01d3a95b2f90bfd5d26c937909e8becc9c6feb7bda1e1b6caca9b47a2a1a07';
export const committedSnapshotSha256='2019e6e3f59cb6b706d57447ae28c9d401ec51eea65c438b83c7f0aa2fb63567';
const forbiddenEnvironment=/^(?:DATABASE_URL|PGPASSWORD|PGSERVICE|PGHOST|PGPORT|PGDATABASE|PGUSER|NEXTAUTH_SECRET|CW_|CONNECTWISE_|NESSUS_|CROWDSTRIKE_|ELASTIC_|VULNERS_|GVM_|ARTEMIS_|ZAP_|SPIDERFOOT_|N8N_|OPENCTI_|MISP_|INTEL_)/;

export function assertCleanEnvironment(env){
 if(Object.keys(env).some(key=>forbiddenEnvironment.test(key)))deny('Inherited database or provider environment is forbidden.');
}

export function assertStageBaseline(config,evidence,precommitSnapshotSha256,precommitAuthority){
 const committed=/^gate34_(?:repeat|authority|app)_/.test(config.database);
 const fault=config.database.startsWith('gate34_fault_');
 if(committed&&(config.sourceDump?.kind!=='postcommit'||
  evidence.snapshotSha256!==committedSnapshotSha256||evidence.ledger.length!==1||
  evidence.ledger[0].id!=='gmi-valor-v1'||evidence.relationships.sourceCustomers.length!==0||
  evidence.ledger[0].company_lineage!==2||evidence.ledger[0].scan_reference_lineage!==2||
  evidence.ledger[0].scheduler_lineage!==8||evidence.aliases?.legacySourcePrefixes!==0||
  evidence.aliases.mappingsRecorded!==true||
  evidence.authority?.mode!=='legacy'||evidence.authority.enforced!==true||
  evidence.authority.epoch!=='1'||evidence.authority.revision!=='1'))
  deny('Committed disposable baseline mismatch.');
 if(fault&&(config.sourceDump?.kind!=='precommit'||evidence.ledger.length!==0||
  evidence.relationships.sourceCustomers.join(',')!=='CO-9150,CO-9153'||
  (precommitSnapshotSha256&&evidence.snapshotSha256!==precommitSnapshotSha256)||
  (precommitAuthority&&JSON.stringify(evidence.authority)!==JSON.stringify(precommitAuthority))))
  deny('Precommit disposable baseline mismatch.');
}

export function parseDisposableTarget(value){
 if(!value||typeof value!=='object'||!rootPattern.test(value.root))deny('Invalid disposable evidence root.');
 if(value.socket!==`${value.root}/socket`)deny('Invalid disposable socket.');
 if(!databasePattern.test(value.database))deny('Invalid disposable database name.');
 if(!value.database.endsWith(value.root.slice(value.root.lastIndexOf('-')+1)))
  deny('Disposable database and evidence root identities differ.');
 if(value.port!==55484)deny('Invalid disposable port.');
 if(value.user!=='codex')deny('Invalid disposable database user.');
 return {root:value.root,socket:value.socket,database:value.database,port:value.port,user:value.user};
}

export function validateRehearsalConfig(config,mode){
 const target=parseDisposableTarget(config);
 if(!/^[a-f0-9]{40}$/.test(config.expectedCommit??''))deny('Exact reviewed Git commit required.');
 const role=mode==='repeat'?'repeat':mode.startsWith('fault-')?'fault_'+mode.slice(6):
  mode==='authority'?'authority':mode==='restore'?'restore':mode==='app'?'app':null;
 if(!['preflight','fingerprint','repeat','authority','restore','app',
  'fault-before','fault-companies','fault-scans','fault-findings','fault-assets','fault-tickets','fault-commit'].includes(mode))
  deny('Invalid Gate 3 rehearsal mode.');
 if(role&&!target.database.startsWith(`gate34_${role}_`))deny('Disposable database does not match rehearsal mode.');
 const dump=config.sourceDump;
 if(!dump||!/^[a-f0-9]{64}$/.test(dump.sha256))deny('Verified backup SHA-256 required.');
 if(mode.startsWith('fault-')){
  if(dump.kind!=='precommit'||dump.path!==precommitBackup.path||dump.sha256!==precommitBackup.sha256)
   deny('Fault injection requires the pinned precommit backup.');
 }else if(['repeat','authority','app'].includes(mode)){
  if(dump.kind!=='postcommit'||dump.path!==`${target.root}/committed.dump`)
   deny('The verified postcommit backup is required.');
 }else if(!['precommit','postcommit','disposable'].includes(dump.kind)||typeof dump.path!=='string'||!dump.path.startsWith('/home/codex/vuln-recovery/'))
  deny('Invalid backup scope.');
 if(mode==='restore'&&(dump.kind!=='disposable'||dump.path!==`${target.root}/disposable-backup.dump`))
  deny('Restore verification requires the independent disposable backup.');
 if(['repeat','authority','app'].includes(mode)&&config.expectedSnapshotSha256!==committedSnapshotSha256)
  deny('Committed snapshot digest changed.');
 if(['repeat','fault-before','fault-companies','fault-scans','fault-findings','fault-assets','fault-tickets','fault-commit'].includes(mode)){
  if(config.manifestSha256!==verifiedManifestSha256||config.planHash!==verifiedPlanHash||
   config.manifestPath!=='/home/codex/vuln-recovery/customer-verified-manifest-ygkf_nxc/manifest.json')
   deny('Verified consolidation manifest or plan hash required.');
 }
 return target;
}

export function assertDisposableIdentity(target,identity){
 const expected=parseDisposableTarget(target);
 if(identity?.database!==expected.database||Number(identity.version)<180000||Number(identity.version)>=190000)
  deny('Disposable database identity mismatch.');
 if(identity.serverAddress!==null||identity.listenAddresses!==''||
    !identity.sockets?.split(',').map(v=>v.trim()).includes(expected.socket))
  deny('Disposable cluster must be socket-only.');
 if(identity.dataDirectory!==`${expected.root}/data`)
  deny('Disposable data directory mismatch.');
}
