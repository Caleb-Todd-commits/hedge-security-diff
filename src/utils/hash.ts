import { createHash } from "node:crypto";

export function stableHash(value: unknown, length = 16): string {
  const normalized = stableStringify(value);
  return createHash("sha256").update(normalized).digest("hex").slice(0, length);
}

/**
 * Deterministic JSON-compatible serialization.
 *
 * Object properties whose value is undefined are omitted, matching
 * JSON.stringify. Undefined array elements become null. This is important for
 * durable state digests because optional TypeScript properties disappear when
 * a register is written to disk and parsed again.
 */
export function stableStringify(value: unknown): string {
  if (value === undefined || typeof value === "function" || typeof value === "symbol") {
    return "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(
        ([, nested]) =>
          nested !== undefined && typeof nested !== "function" && typeof nested !== "symbol"
      )
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, nested]) => `${JSON.stringify(key)}:${stableStringify(nested)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}
