import { describe, expect, it } from "vitest";
import { parseFixCommand, parsePruneCommand } from "../../src/remediation/commands.js";

describe("Hedge comment commands", () => {
  it("parses a fix command case-insensitively", () => {
    expect(parseFixCommand("@HEDGE fix hedge-012")).toEqual({ riskId: "HEDGE-012" });
  });

  it("does not accept a malformed risk ID", () => {
    expect(parseFixCommand("@hedge fix 12")).toBeNull();
  });

  it("requires an explicit risk-acceptance reason", () => {
    expect(parsePruneCommand('@hedge prune HEDGE-012 reason:"internal-only"')).toEqual({
      riskId: "HEDGE-012",
      reason: "internal-only"
    });
    expect(parsePruneCommand("@hedge prune HEDGE-012")).toBeNull();
  });
});
