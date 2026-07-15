import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadHedgeContext, parseContextText, saveHedgeContext } from "../../src/config/context.js";

describe("reviewed Hedge context", () => {
  it("uses empty reviewed facts by default", () => {
    expect(parseContextText(undefined)).toEqual({
      sensitive_assets: [],
      internet_facing: [],
      authentication: [],
      privileged_roles: [],
      trusted_external_services: [],
      notes: []
    });
  });

  it("parses the five high-value context fields", () => {
    const context = parseContextText(`
sensitive_assets:
  - customer records
internet_facing:
  - public API
authentication:
  - Clerk
privileged_roles:
  - administrator
trusted_external_services:
  - Stripe
notes:
  - production deployment
`);
    expect(context.sensitive_assets).toEqual(["customer records"]);
    expect(context.internet_facing).toEqual(["public API"]);
    expect(context.authentication).toEqual(["Clerk"]);
    expect(context.privileged_roles).toEqual(["administrator"]);
    expect(context.trusted_external_services).toEqual(["Stripe"]);
  });

  it("round-trips reviewed context through .hedge/context.yml", async () => {
    const root = await mkdtemp(join(tmpdir(), "hedge-context-"));
    const path = await saveHedgeContext(root, {
      sensitive_assets: ["signing key"],
      internet_facing: ["webhook"],
      authentication: ["OIDC"],
      privileged_roles: ["maintainer"],
      trusted_external_services: ["GitHub"],
      notes: ["reviewed"]
    });
    expect(await readFile(path, "utf8")).toContain("signing key");
    expect(await loadHedgeContext(root)).toMatchObject({
      authentication: ["OIDC"],
      privileged_roles: ["maintainer"]
    });
  });
});
