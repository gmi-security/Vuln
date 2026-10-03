// Shared request-body validation for API routes. The store functions these
// routes call (createCompany, updateCompany, createCompensatingControl,
// createFolder, etc.) call .trim() on their string inputs unconditionally --
// a route's TypeScript body type (e.g. `name?: string`) is a compile-time
// hint only and enforces nothing at runtime, so a JSON body with a number,
// object, or array in a "string" field reaches .trim() unchanged and throws
// an unhandled TypeError (a generic 500) instead of a clean 400.
export function stringFieldError(
  body: Record<string, unknown>,
  fields: string[],
): string | null {
  for (const field of fields) {
    const value = body[field];
    if (value !== undefined && value !== null && typeof value !== "string") {
      return `"${field}" must be a string.`;
    }
  }
  return null;
}
