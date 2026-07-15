import { describe, expect, it } from "vitest";
import { isResolvedRisk, isUnresolvedRisk } from "../../src/register/status.js";

describe("risk resolution semantics", () => {
  it.each(["open", "mitigation-detected", "verification-available"] as const)(
    "treats %s as unresolved",
    (status) => {
      expect(isUnresolvedRisk({ status })).toBe(true);
      expect(isResolvedRisk({ status })).toBe(false);
    }
  );

  it.each(["verified", "accepted", "closed"] as const)("treats %s as resolved", (status) => {
    expect(isUnresolvedRisk({ status })).toBe(false);
    expect(isResolvedRisk({ status })).toBe(true);
  });
});
