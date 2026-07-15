import { describe, expect, it } from "vitest";
import { parseConfigText } from "../../src/config/load.js";

describe("Hedge configuration", () => {
  it("applies safe defaults", () => {
    const config = parseConfigText(undefined);
    expect(config.framework).toBe("auto");
    expect(config.fail_on).toBe("high");
  });

  it("parses a minimal repository policy", () => {
    const config = parseConfigText(
      "framework: nextjs\nfail_on: critical\nignored_paths:\n  - docs/**\n"
    );
    expect(config.framework).toBe("nextjs");
    expect(config.fail_on).toBe("critical");
    expect(config.ignored_paths).toEqual(["docs/**"]);
  });

  it("rejects unsupported severity values", () => {
    expect(() => parseConfigText("fail_on: catastrophic\n")).toThrow();
  });
});
