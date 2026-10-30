// Record durations and controlled phase labels only, never SQL or parameters.
export function observePublicationQueries(client,{now=()=>performance.now(),emit=value=>console.info(JSON.stringify(value))}={}) {
  let phase='prepare',offset=0,bytes=0,transactionAt=null,lastEnd=null,lastLog=now();
  let queries=0,maxQueryMs=0,maxIdleGapMs=0,maxTransactionMs=0;
  const report=(event,code)=>{
    emit({at:new Date().toISOString(),event,role:process.env.VULN_RUNTIME_ROLE??'worker',pid:process.pid,
      backendPid:client.processID,phase,offset,bytes,queries,code,
      maxQueryMs:Math.round(maxQueryMs),maxIdleGapMs:Math.round(maxIdleGapMs),maxTransactionMs:Math.round(maxTransactionMs)});
    lastLog=now();
  };
  return {
    phase(value,details={}) { phase=value;offset=details.offset??0;bytes=details.bytes??0; },
    async query(sql,params) {
      const start=now(),gap=transactionAt!==null&&lastEnd!==null?start-lastEnd:0;
      if(/^BEGIN\b/.test(sql))transactionAt=start;
      let failure;
      try { return await client.query(sql,params); }
      catch(error){failure=error;throw error;}
      finally {
        const end=now(),duration=end-start;
        queries++;maxQueryMs=Math.max(maxQueryMs,duration);maxIdleGapMs=Math.max(maxIdleGapMs,gap);
        if(transactionAt!==null)maxTransactionMs=Math.max(maxTransactionMs,end-transactionAt);
        lastEnd=end;
        if(failure||duration>=1000||gap>=1000)report('publication-query-slow-or-failed',failure?.code);
        else if(end-lastLog>=30000)report('publication-progress');
        if(/^(COMMIT|ROLLBACK)\b/.test(sql))transactionAt=null;
      }
    },
    close(){report('publication-attempt-finished');},
  };
}
