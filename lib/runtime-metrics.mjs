import {monitorEventLoopDelay,performance,PerformanceObserver} from 'node:perf_hooks';

export function startRuntimeMetrics({role,emit=sample=>{
  console.info(JSON.stringify(sample));
  if(process.connected)process.send?.({type:'runtime-metrics'});
}}) {
  const delay=monitorEventLoopDelay({resolution:20});delay.enable();
  let previous=performance.eventLoopUtilization(),gcMs=0;
  const gc=new PerformanceObserver(list=>{for(const entry of list.getEntries())gcMs+=entry.duration;});
  gc.observe({entryTypes:['gc']});
  const timer=setInterval(()=>{
    const memory=process.memoryUsage(),current=performance.eventLoopUtilization(),utilization=performance.eventLoopUtilization(current,previous);
    previous=current;
    emit({at:new Date().toISOString(),event:'runtime-metrics',role,pid:process.pid,
      rssBytes:memory.rss,heapUsedBytes:memory.heapUsed,heapTotalBytes:memory.heapTotal,externalBytes:memory.external,
      eventLoopMaxMs:Math.round(delay.max/1e6),eventLoopP99Ms:Math.round(delay.percentile(99)/1e6),
      eventLoopUtilization:Math.round(utilization.utilization*1000)/1000,gcMs:Math.round(gcMs)});
    delay.reset();gcMs=0;
  },10000);
  timer.unref?.();
  return ()=>{clearInterval(timer);delay.disable();gc.disconnect();};
}
