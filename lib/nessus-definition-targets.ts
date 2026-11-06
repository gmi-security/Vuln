import { isIP } from "node:net";
import { scannerExactTargetKey } from "./scanner-target-scope";

// The installed GMI Nessus returns settings.basic.inputs[].id =
// "text_targets" with the configured string in .default; other Nessus
// editions may use .value. Neither a schedule nor imported findings is a
// per-occurrence target source. This parser is pure, read-only, fail-closed.
// It is used only for TARGET PLAN PREVIEWS. Verified host results for a
// specific completed Nessus occurrence are still required before dispatch.
export type NessusDefinitionTargetSet = {
  targets: string[];
  expressions: number;
  duplicateSlots: number;
  cidrExpressions: number;
};

function ip4Number(text: string): number {
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(text) ||
      isIP(text) !== 4) throw new Error("Invalid IPv4 CIDR address.");
  return text.split(".").reduce((n,part) => n * 256 + Number(part), 0) >>> 0;
}

function ip4Text(ip: number): string {
  return [(ip >>> 24) & 255, (ip >>> 16) & 255,
    (ip >>> 8) & 255, ip & 255].join(".");
}

function targetsForExpression(text: string): string[] {
  const cidr=text.match(/^((?:\d{1,3}\.){3}\d{1,3})\/([0-9]|[12][0-9]|3[0-2])$/);
  if (cidr) {
    const address=ip4Number(cidr[1]), prefix=Number(cidr[2]);
    const count=2 ** (32-prefix);
    if (count>1024) throw new Error("Nessus network requires separate bounded expansion approval.");
    const base=Math.floor(address/count)*count;
    return Array.from({length:count},(_,i)=>ip4Text(base+i));
  }
  // Catch all unsupported ranges/exclusions/wildcards. In particular,
  // 192.0.2.1-192.0.2.10 must never masquerade as a hostname.
  if (/[!,*]/.test(text) || /^\d+(?:\.\d+){2,3}[-]/.test(text))
    throw new Error("Nessus target expression requires review.");
  scannerExactTargetKey(text);
  return [text.toLowerCase().replace(/\.$/,"")];
}

export function readNessusDefinitionTargets(editor: unknown): NessusDefinitionTargetSet {
  if(!editor||typeof editor!=="object"||Array.isArray(editor))
    throw new Error("Missing Nessus editor response.");
  const settings=(editor as {settings?:unknown}).settings;
  const basic=settings&&typeof settings==="object"&&!Array.isArray(settings)
    ? (settings as {basic?:unknown}).basic : null;
  const inputs=basic&&typeof basic==="object"&&!Array.isArray(basic)
    ? (basic as {inputs?:unknown}).inputs : null;
  if(!Array.isArray(inputs))throw new Error("Missing Nessus text_targets input array.");
  const fields=inputs.filter(x=>x&&typeof x==="object"&&!Array.isArray(x)&&
    ((x as {id?:unknown}).id==="text_targets"||
     (x as {name?:unknown}).name==="text_targets"));
  if(fields.length!==1)throw new Error("Ambiguous Nessus target descriptor.");
  const descriptor=fields[0] as {value?:unknown;default?:unknown};
  if(descriptor.value!==undefined&&descriptor.value!==null &&
     typeof descriptor.value!=="string")
    throw new Error("Invalid Nessus target value field.");
  if(descriptor.default!==undefined&&descriptor.default!==null &&
     typeof descriptor.default!=="string")
    throw new Error("Invalid Nessus target default field.");
  const configured=typeof descriptor.value==="string"?descriptor.value.trim():"";
  const saved=typeof descriptor.default==="string"?descriptor.default.trim():"";
  if(configured&&saved&&configured!==saved)
    throw new Error("Conflicting Nessus target descriptor values.");
  const value=configured||saved;
  if(!value)throw new Error("Nessus target descriptor is empty.");
  const expressions=value.split(/[,\s]+/).filter(Boolean);
  if(expressions.length===0||expressions.length>4096)
    throw new Error("Excessive Nessus target expressions.");
  const targets=new Map<string,string>();
  let duplicateSlots=0,cidrExpressions=0;
  for(const expression of expressions){
    const expanded=targetsForExpression(expression);
    if(expression.includes("/"))cidrExpressions++;
    for(const host of expanded){
      const key=scannerExactTargetKey(host);
      if(targets.has(key)){duplicateSlots++;continue}
      if(targets.size>=4096)
        throw new Error("Nessus expanded target count exceeds review limit.");
      targets.set(key,host);
    }
  }
  if(!targets.size)throw new Error("No valid Nessus configured targets.");
  return {targets:[...targets.values()],expressions:expressions.length,
    duplicateSlots,cidrExpressions};
}
