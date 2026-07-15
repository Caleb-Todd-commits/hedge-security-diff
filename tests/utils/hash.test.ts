import { describe, expect, it } from "vitest";
import { stableHash, stableStringify } from "../../src/utils/hash.js";

describe("stable JSON hashing", () => {
  it("is insensitive to object key order", () => {
    expect(stableHash({ a: 1, b: 2 })).toBe(stableHash({ b: 2, a: 1 }));
  });

  it("matches JSON persistence semantics for undefined object values", () => {
    expect(stableStringify({ a: 1, optional: undefined })).toBe(stableStringify({ a: 1 }));
  });

  it("normalizes undefined array entries to null", () => {
    expect(stableStringify([1, undefined, 3])).toBe("[1,null,3]");
  });
});
