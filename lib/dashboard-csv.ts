import type { QueryResult } from "./elastic-dashboard";

export function dashboardCsv(result: QueryResult): string {
  const cell = (value: string | number | boolean | null) => {
    let text = value === null ? "" : String(value);
    // Treat exported source strings as data, never spreadsheet formulas.
    if (typeof value === "string" && /^[\s\uFEFF]*[=+@-]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  return "\uFEFF" + [result.columns.map((column) => column.name), ...result.rows]
    .map((row) => row.map(cell).join(",")).join("\r\n") + "\r\n";
}
