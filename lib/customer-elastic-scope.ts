// Pure scope policy, shared by approval and execution. Dataset ownership must
// be verified by the operator; a dataset containing several customers is not
// eligible for this whole-dataset approval.
export function elasticDatasets(value: unknown): string[] {
  if (!Array.isArray(value) || !value.length || value.length > 100 ||
      value.some(v => typeof v !== "string" || !/^[a-z0-9][a-z0-9._-]{0,199}$/.test(v)) ||
      new Set(value).size !== value.length) throw new Error("Approve exact Elasticsearch index or data stream names without aliases, wildcards or shared-customer datasets.");
  return [...value].sort();
}

const commands = new Set(["WHERE", "EVAL", "STATS", "KEEP", "DROP", "RENAME", "SORT", "LIMIT", "MV_EXPAND", "DISSECT", "GROK"]);
function invalid(): never { throw new Error("Customer-scoped ES|QL supports one FROM and standard filtering, aggregation and table commands. Joins, enrichment, subqueries, block comments and external sources need a separate review."); };

// This is a deliberately restricted pipeline, not a general ES|QL parser.
// Preserve quoted pipes; never let a quoted string or nested pipeline hide an
// additional source command. Unsupported syntax fails before any source call.
function pipeline(query: string): string[] {
  const parts: string[] = []; let start = 0, quote = "", depth = 0;
  for (let i = 0; i < query.length; i++) {
    const ch = query[i];
    if (quote) {
      if (ch === "\\" && quote === '"') { if (!['"', "\\", "n", "r", "t"].includes(query[++i])) invalid(); }
      else if (ch === quote) { if (quote === "`" && query[i + 1] === "`") i++; else quote = ""; }
      continue;
    }
    if (ch === '"' || ch === "`") {
      if (query.slice(i, i + 3) === '"""') invalid();
      quote = ch; continue;
    }
    if (query.slice(i, i + 2) === "//") {
      const newline = query.indexOf("\n", i), end = newline < 0 ? query.length : newline;
      query = query.slice(0, i) + " ".repeat(end - i) + query.slice(end);
      i = end - 1; continue;
    }
    if (ch === "'" || ch === ";" || ch === "\\" || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(ch) ||
        query.slice(i, i + 2) === "/*" || query.slice(i, i + 2) === "*/") invalid();
    if (query.slice(i, i + 4).toUpperCase() === "FROM" && !/[A-Za-z0-9_]/.test(query[i - 1] ?? "") &&
        !/[A-Za-z0-9_]/.test(query[i + 4] ?? "") && query.slice(0, i).trim()) invalid();
    if (ch === "(") depth++;
    if (ch === ")" && --depth < 0) invalid();
    if (ch === "|") { if (depth) invalid(); parts.push(query.slice(start, i).trim()); start = i + 1; }
  }
  if (quote || depth) invalid();
  parts.push(query.slice(start).trim());
  if (parts.some(p => !p)) invalid();
  return parts;
}

export function customerEsql(query: string, approved: string[]) {
  const datasets = elasticDatasets(approved);
  if (typeof query !== "string" || !query.trim() || query.length > 16000) invalid();
  const parts = pipeline(query);
  const from = /^FROM\s+([a-z0-9.*_-]+(?:\s*,\s*[a-z0-9.*_-]+)*)(?:\s+METADATA\s+(_[a-z]+(?:\s*,\s*_[a-z]+)*))?$/i.exec(parts[0]);
  if (!from) invalid();
  const selected = new Set<string>();
  for (const pattern of from[1].split(",").map(p => p.trim())) {
    // Only '*' has wildcard meaning. A requested pattern is intersected with
    // the reviewed exact names; it is never sent upstream.
    // Literal segments avoid exponential regular-expression backtracking for
    // a user-supplied pattern with many alternating stars and repeated text.
    const segments = pattern.split("*");
    const matches = datasets.filter(name => {
      if (segments.length === 1) return name === pattern;
      if (!name.startsWith(segments[0])) return false;
      let offset = segments[0].length;
      for (const part of segments.slice(1, -1)) {
        const found = name.indexOf(part, offset);
        if (found < 0) return false;
        offset = found + part.length;
      }
      const last = segments[segments.length - 1];
      return name.endsWith(last) && name.length - last.length >= offset;
    });
    if (!matches.length) throw new Error("Every FROM pattern must match an approved dataset for this customer.");
    matches.forEach(name => selected.add(name));
  }
  for (const part of parts.slice(1)) {
    const command = /^([A-Z_]+)\s+\S/i.exec(part)?.[1].toUpperCase();
    if (!command || !commands.has(command)) invalid();
  }
  return { datasets: [...selected].sort(), suffix: `${from[2] ? ` METADATA ${from[2]}` : ""}${parts.length > 1 ? `\n| ${parts.slice(1).join("\n| ")}` : ""}` };
}

export function resolvedElasticIndices(datasets: string[], body: Record<string, unknown>): string[] {
  const fail = (): never => { throw new Error("Approved Elasticsearch datasets could not be resolved to local physical indexes. Aliases, missing datasets and shared backing indexes are not supported."); };
  const expected = new Set(elasticDatasets(datasets)), seen = new Set<string>(), physical = new Set<string>();
  if (!Array.isArray(body.indices) || !Array.isArray(body.data_streams) || !Array.isArray(body.aliases) || body.aliases.length) fail();
  const add = (name: unknown) => {
    if (typeof name !== "string" || !/^(?:[a-z0-9][a-z0-9._-]{0,199}|\.ds-[a-z0-9._-]{1,250})$/.test(name) || physical.has(name)) fail();
    physical.add(name as string);
  };
  for (const item of [...body.indices as any[], ...body.data_streams as any[]]) {
    if (!item || !expected.has(item.name) || seen.has(item.name)) fail();
    seen.add(item.name);
    if ((body.data_streams as unknown[]).includes(item)) {
      if (!Array.isArray(item.backing_indices) || !item.backing_indices.length) fail();
      item.backing_indices.forEach(add);
    } else {
      if (item.data_stream || !Array.isArray(item.attributes) || !item.attributes.includes("open") || item.attributes.includes("closed")) fail();
      add(item.name);
    }
  }
  if (seen.size !== expected.size || !physical.size || physical.size > 500) fail();
  return [...physical].sort();
}
