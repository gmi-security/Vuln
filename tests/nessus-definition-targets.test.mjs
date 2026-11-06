// node --experimental-vm-modules --test tests/nessus-definition-targets.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {isIP} from "node:net";
import ts from "typescript";
import {SourceTextModule,SyntheticModule} from "node:vm";

const source=await readFile("lib/nessus-definition-targets.ts","utf8");
const js=ts.transpileModule(source,{compilerOptions:{
  target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext
}}).outputText;
const exactKey=value=>{
  if(typeof value!=="string"||!value||value!==value.trim()||
     /[*!,/]/.test(value)||value.includes("://")||
     (/^\d[\d.-]*$/.test(value) && isIP(value)!==4))
    throw Error("Invalid exact target");
  return value.toLowerCase().replace(/\.$/,"");
};
const m=new SourceTextModule(js);
await m.link(async spec=>{
  if(spec==="node:net")return new SyntheticModule(["isIP"],function(){
    this.setExport("isIP",isIP);
  });
  assert.equal(spec,"./scanner-target-scope");
  return new SyntheticModule(["scannerExactTargetKey"],function(){
    this.setExport("scannerExactTargetKey",exactKey);
  });
});
await m.evaluate();
const {readNessusDefinitionTargets:parse}=m.namespace;
const editor=defaultValue=>({settings:{basic:{inputs:[
  {id:"schedule",value:"not-targets"},
  {id:"text_targets",name:"textarea",default:defaultValue}
]}}});

test("real Nessus shape reads default text_targets without choosing schedule",()=>{
  const r=parse(editor("ALPHA.example., 192.0.2.1\nbravo.example"));
  assert.deepEqual([...r.targets],["alpha.example","192.0.2.1","bravo.example"]);
  assert.equal(r.expressions,3);
  assert.equal(r.duplicateSlots,0);
});
test("duplicates within one source definition are counted, not scheduled twice",()=>{
  const r=parse(editor("ALPHA.example., alpha.example 192.0.2.1"));
  assert.equal(r.targets.length,2);
  assert.equal(r.duplicateSlots,1);
});
test("bounded CIDR expands to the complete candidate address space",()=>{
  const r=parse(editor("192.0.2.0/30,alpha.example"));
  assert.equal(r.targets.length,5);
  assert.equal(r.cidrExpressions,1);
});
test("overlapping exact IP with CIDR is counted once",()=>{
  const r=parse(editor("192.0.2.0/30,192.0.2.2"));
  assert.equal(r.targets.length,4);
  assert.equal(r.duplicateSlots,1);
});
test("range, wildcard, network bigger than cap and malformed IP fail closed",()=>{
  for(const target of ["192.0.2.1-192.0.2.10","*.example",
     "10.0.0.0/8","999.9.9.9","192.0.2.1,!192.0.2.2"]){
    assert.throws(()=>parse(editor(target)));
  }
});
test("ambiguous, missing and inconsistent source fields fail closed",()=>{
  const bad=[
    {settings:{basic:{inputs:[]}}},
    {settings:{basic:{inputs:[
      {id:"text_targets",default:"a.example"},
      {id:"text_targets",default:"b.example"}]}}},
    {settings:{basic:{inputs:[
      {id:"text_targets",value:"a.example",default:"b.example"}]}}},
    {settings:{basic:{inputs:[{id:"text_targets",default:[]}]}}},
    {settings:{basic:{inputs:[{id:"text_targets",default:""}]}}},
  ];
  for(const e of bad)assert.throws(()=>parse(e));
});
test("zero target side effects or network operations in pure source parser",()=>{
  const text=source;
  assert.doesNotMatch(text,/fetch\(|http\.request|startScan\(|POST|vulnersBridgeStartScan/);
});
