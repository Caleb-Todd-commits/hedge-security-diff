import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  assertTrustedStagePaths,
  recordedDecision,
  resolveStagePaths,
  runReasonStage,
  writeCollectionStage
} from "../../src/action/stages.js";
import { parseConfigText } from "../../src/config/load.js";
import { HedgeContextSchema } from "../../src/domain/schemas.js";
import { checkHedge } from "../../src/core/run.js";
import { currentActionVersion, currentWorkflowRef } from "../../src/pipeline/metadata.js";
import { emptyRegister } from "../../src/register/store.js";
import { computeRunManifestDigest, serializeRunManifest } from "../../src/github/run-manifest.js";

const execFileAsync = promisify(execFile);
const previousWorkflowRef = process.env.GITHUB_WORKFLOW_REF;
const previousWorkflowSha = process.env.GITHUB_WORKFLOW_SHA;
const previousActionRef = process.env.HEDGE_ACTION_REF;
const previousGithubActions = process.env.GITHUB_ACTIONS;
const previousRunnerTemp = process.env.RUNNER_TEMP;

describe("credential-separated Action stages", () => {
  beforeEach(() => {
    process.env.GITHUB_WORKFLOW_REF =
      "example/repository/.github/workflows/hedge.yml@refs/heads/main";
    process.env.GITHUB_WORKFLOW_SHA = "e".repeat(40);
    process.env.HEDGE_ACTION_REF = "example/hedge@0123456789012345678901234567890123456789";
  });

  afterEach(() => {
    restoreEnv("GITHUB_WORKFLOW_REF", previousWorkflowRef);
    restoreEnv("GITHUB_WORKFLOW_SHA", previousWorkflowSha);
    restoreEnv("HEDGE_ACTION_REF", previousActionRef);
    restoreEnv("GITHUB_ACTIONS", previousGithubActions);
    restoreEnv("RUNNER_TEMP", previousRunnerTemp);
  });

  it("hands exact collection bytes to deterministic reasoning through bound manifests", async () => {
    const fixture = await createFixture();
    const reason = await runReasonStage({
      paths: fixture.paths,
      expected: fixture.bindings
    });
    expect(reason.bundle.analysis.surfaceChanged).toBe(true);
    expect(reason.bundle.analysis.model).toBe("deterministic-only");
    expect(reason.bundle.collectionManifestDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(await readFile(reason.manifestPath, "utf8")).toContain('"reason.json"');
  });

  it("fails closed when collection bytes are changed after collection", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.collectionPath, '{"tampered":true}\n');
    await expect(
      runReasonStage({ paths: fixture.paths, expected: fixture.bindings })
    ).rejects.toThrow(/digest mismatch/i);
  });

  it("rejects manifest metadata that disagrees with its validated collection", async () => {
    const fixture = await createFixture();
    const manifest = JSON.parse(await readFile(fixture.paths.collectionManifestPath, "utf8"));
    manifest.model = "fabricated-model";
    manifest.manifestDigest = computeRunManifestDigest(manifest);
    await writeFile(
      fixture.paths.collectionManifestPath,
      serializeRunManifest(manifest as Parameters<typeof serializeRunManifest>[0])
    );

    await expect(
      runReasonStage({ paths: fixture.paths, expected: fixture.bindings })
    ).rejects.toThrow(/manifest model does not match/i);
  });

  it("requires runner-owned paths and rejects a preplanted symlink directory", async () => {
    const fixture = await createFixture({ writeStage: false });
    const runnerTemp = await mkdtemp(join(tmpdir(), "hedge-runner-temp-"));
    const outside = await mkdtemp(join(tmpdir(), "hedge-stage-outside-"));
    process.env.GITHUB_ACTIONS = "true";
    process.env.RUNNER_TEMP = runnerTemp;

    expect(() => assertTrustedStagePaths(resolveStagePaths(fixture.root), "collect")).toThrow(
      /runner\.temp/i
    );

    const preplanted = join(runnerTemp, "preplanted");
    const collectionDirectory = join(preplanted, "nested");
    await symlink(outside, preplanted);
    const paths = resolveStagePaths(fixture.root, {
      collectionPath: join(collectionDirectory, "collection.json"),
      collectionManifestPath: join(collectionDirectory, "collection-manifest.json")
    });
    assertTrustedStagePaths(paths, "collect");
    await expect(
      writeCollectionStage({
        paths,
        result: fixture.result,
        config: fixture.config,
        context: fixture.context,
        register: emptyRegister(),
        patch: "",
        repository: "example/repository",
        pullRequest: 17,
        baseSha: fixture.baseSha,
        headSha: fixture.headSha
      })
    ).rejects.toThrow(/symlink/i);
    await expect(access(join(outside, "nested"))).rejects.toThrow();
  });

  it("does not report allow when analysis health recorded a warning", () => {
    expect(
      recordedDecision({
        summary: "Coverage was partial.",
        surfaceChanged: false,
        findings: [],
        decisions: [
          {
            id: "threshold",
            type: "allow",
            reason: "No finding met the threshold.",
            source: "threshold",
            riskFingerprints: [],
            invariantIds: [],
            observationIds: [],
            inferenceIds: []
          },
          {
            id: "health",
            type: "warn",
            reason: "Coverage was partial.",
            source: "analysis-health",
            riskFingerprints: [],
            invariantIds: [],
            observationIds: [],
            inferenceIds: []
          }
        ],
        integrity: {
          untrustedInstructionsObserved: false,
          analysisBoundaryHeld: true,
          notes: []
        },
        limitations: []
      })
    ).toBe("warn");
  });
});

async function createFixture(options: { writeStage?: boolean } = {}) {
  const root = await mkdtemp(join(process.env.RUNNER_TEMP || tmpdir(), "hedge-stages-"));
  await git(root, ["init", "--quiet"]);
  await git(root, ["config", "user.email", "hedge-tests@example.invalid"]);
  await git(root, ["config", "user.name", "Hedge Tests"]);
  await mkdir(join(root, "app/api/items"), { recursive: true });
  await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { next: "15.0.0" } }));
  const route = join(root, "app/api/items/route.ts");
  await writeFile(route, "export function GET() { return Response.json({ ok: true }); }\n");
  const baseSha = await commitAll(root, "base");
  await writeFile(
    route,
    "export async function POST(request: Request) { await prisma.item.create({ data: await request.json() }); return Response.json({ ok: true }); }\n"
  );
  const headSha = await commitAll(root, "head");
  const config = parseConfigText("framework: nextjs\n");
  const context = HedgeContextSchema.parse({});
  const result = await checkHedge({
    root,
    config,
    context,
    repository: "example/repository",
    baseRevision: baseSha,
    headRevision: headSha,
    baselineRegister: emptyRegister()
  });
  const paths = resolveStagePaths(root);
  if (options.writeStage !== false) {
    await writeCollectionStage({
      paths,
      result,
      config,
      context,
      register: emptyRegister(),
      patch: "",
      repository: "example/repository",
      pullRequest: 17,
      baseSha,
      headSha
    });
  }
  return {
    root,
    paths,
    result,
    config,
    context,
    baseSha,
    headSha,
    bindings: {
      repository: "example/repository",
      pullRequest: 17,
      baseSha,
      headSha,
      workflowRef: currentWorkflowRef(),
      actionVersion: currentActionVersion()
    }
  };
}

async function commitAll(root: string, message: string): Promise<string> {
  await git(root, ["add", "--all"]);
  await git(root, ["commit", "--quiet", "-m", message]);
  const { stdout } = await git(root, ["rev-parse", "HEAD"]);
  return stdout.trim().toLowerCase();
}

async function git(root: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync("git", args, { cwd: root, encoding: "utf8", maxBuffer: 2_000_000 });
}

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
