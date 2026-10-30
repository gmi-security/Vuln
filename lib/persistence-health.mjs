const safeCode=code=>/^[0-9A-Z]{5}$/.test(code??'')||
  ['ECONNRESET','ECONNREFUSED','ETIMEDOUT','platform-save-timeout','platform-writer-stale','platform-capture-changed','platform-publication-deferred'].includes(code)?code:'UNKNOWN';

// A retained last-known phase is history, not proof the worker is still saving.
export function persistenceNotice(status){
  if(status.persistBlocked??status.persistence?.blocked)return 'blocked';
  if(status.worker?.available===false)return 'unavailable';
  return status.persistenceState??'healthy';
}

export function createPersistenceHealth({now=Date.now,emit=event=>console.warn(JSON.stringify(event))}={}) {
  let state='healthy',phase='prepare',pending=null,progress=null,retryAt=null,firstError=null,revision=null,committedAt=null,alertAt=null;
  const iso=value=>value===null?null:new Date(value).toISOString();
  const dirty=()=>{if(pending===null){pending=now();progress=pending;}if(state==='healthy')state='publishing';};
  const failure=error=>{firstError??={code:safeCode(error?.cause?.code??error?.code),phase,at:iso(now())};};
  return {
    dirty,
    publishing(value='prepare'){dirty();phase=value;state='publishing';retryAt=null;},
    progress(){progress=now();alertAt=null;},
    retry({code,delayMs}){dirty();failure({code});state='retrying';retryAt=now()+delayMs;},
    failed(error,blocked){dirty();failure(error);state=blocked?'blocked':'retrying';if(!blocked)retryAt=now()+60000;},
    committed(value,laterPending=false){revision=value??revision;committedAt=now();firstError=null;retryAt=null;alertAt=null;
      pending=laterPending?now():null;progress=pending;state=laterPending?'publishing':'healthy';},
    snapshot(){
      const stalled=pending!==null&&now()-(progress??pending)>=300000;
      if(stalled&&(alertAt===null||now()-alertAt>=300000)){
        alertAt=now();emit({at:iso(now()),event:'persistence-stalled',state,pendingSince:iso(pending),lastProgressAt:iso(progress),code:firstError?.code});
      }
      return {persistenceState:state,lastCommittedRevision:revision,lastCommittedAt:iso(committedAt),pendingSince:iso(pending),
        lastProgressAt:iso(progress),nextRetryAt:iso(retryAt),firstError,stalled};
    },
  };
}
