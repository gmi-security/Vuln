import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SourceTextModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/dashboard-layout.ts", import.meta.url), "utf8");
const module = new SourceTextModule(ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText);
await module.link(() => { throw new Error("Unexpected dependency"); }); await module.evaluate();
const { moveTileIds, applyTileOrder } = module.namespace;

test("dragging and arrow moves preserve every tile and leave input untouched", () => {
  const ids = ["coverage", "trend", "patch", "hosts"];
  assert.deepEqual(moveTileIds(ids, "coverage", "hosts"), ["trend", "patch", "hosts", "coverage"]);
  assert.deepEqual(moveTileIds(ids, "hosts", "coverage"), ["hosts", "coverage", "trend", "patch"]);
  assert.deepEqual(moveTileIds(ids, "patch", "trend"), ["coverage", "patch", "trend", "hosts"]);
  assert.equal(moveTileIds(ids, "patch", "patch"), ids);
  assert.equal(moveTileIds(ids, "missing", "patch"), ids);
  assert.deepEqual(ids, ["coverage", "trend", "patch", "hosts"]);
});

test("applying or rolling back layout retains fresh results and newly added tiles", () => {
  const tiles = [{ id: "a", result: 8 }, { id: "b", result: 9 }, { id: "new", result: 10 }];
  const ordered = applyTileOrder(tiles, ["b", "deleted", "a"]);
  assert.deepEqual(ordered.map((tile) => tile.id), ["b", "a", "new"]);
  assert.equal(ordered[0], tiles[1]);
  assert.deepEqual(applyTileOrder(ordered, ["a", "b"]), tiles);
});
