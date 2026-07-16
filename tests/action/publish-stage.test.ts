import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  pullsGet: vi.fn(),
  listComments: vi.fn(),
  deleteComment: vi.fn(),
  context: {
    payload: { pull_request: { number: 17 } },
    repo: { owner: "example", repo: "repository" }
  }
}));

vi.mock("@actions/github", () => ({
  context: mocks.context,
  getOctokit: () => ({
    paginate: async (
      method: (...args: unknown[]) => Promise<{ data: unknown[] }>,
      options: unknown
    ) => (await method(options)).data,
    rest: {
      pulls: { get: mocks.pullsGet },
      issues: {
        listComments: mocks.listComments,
        deleteComment: mocks.deleteComment,
        updateComment: vi.fn(),
        createComment: vi.fn()
      }
    }
  })
}));

import {
  resolveStagePaths,
  runPublishStage,
  writeCollectionStage
} from "../../src/action/stages.js";
import { parseConfigText } from "../../src/config/load.js";
import { HedgeContextSchema } from "../../src/domain/schemas.js";
import { checkHedge } from "../../src/core/run.js";
import { emptyRegister } from "../../src/register/store.js";

const execFileAsync = promisify(execFile);
const previousWorkflowRef = process.env.GITHUB_WORKFLOW_REF;
const previousWorkflowSha = process.env.GITHUB_WORKFLOW_SHA;
const previousActionRef = process.env.HEDGE_ACTION_REF;

describe("write-authorized publisher", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKFLOW_REF =
      "example/repository/.github/workflows/hedge.yml@refs/heads/main";
    process.env.GITHUB_WORKFLOW_SHA = "e".repeat(40);
    process.env.HEDGE_ACTION_REF = "example/hedge@0123456789012345678901234567890123456789";
    mocks.listComments.mockResolvedValue({ data: [] });
    mocks.deleteComment.mockResolvedValue({});
  });

  afterEach(() => {
    restoreEnv("GITHUB_WORKFLOW_REF", previousWorkflowRef);
    restoreEnv("GITHUB_WORKFLOW_SHA", previousWorkflowSha);
    restoreEnv("HEDGE_ACTION_REF", previousActionRef);
  });

  it("publishes only after validating exact current PR bindings", async () => {
    const fixture = await createNoDeltaFixture();
    mocks.pullsGet.mockResolvedValue({
      data: { base: { sha: fixture.sha }, head: { sha: fixture.sha } }
    });
    const result = await runPublishStage({
      root: fixture.root,
      paths: fixture.paths,
      token: "write-token",
      dryRun: true
    });
    expect(result.analysis.confirmedNoDelta).toBe(true);
    expect(result.decision).toBe("allow");
    expect(mocks.pullsGet).toHaveBeenCalledTimes(2);
  });

  it("rejects a run when the PR head changes immediately before publication", async () => {
    const fixture = await createNoDeltaFixture();
    mocks.pullsGet
      .mockResolvedValueOnce({
        data: { base: { sha: fixture.sha }, head: { sha: fixture.sha } }
      })
      .mockResolvedValueOnce({
        data: { base: { sha: fixture.sha }, head: { sha: "f".repeat(40) } }
      });
    await expect(
      runPublishStage({ root: fixture.root, paths: fixture.paths, token: "write-token" })
    ).rejects.toThrow(/stale before publication/i);
    expect(mocks.deleteComment).not.toHaveBeenCalled();
  });
});

async function createNoDeltaFixture() {
  const root = await mkdtemp(join(tmpdir(), "hedge-publish-stage-"));
  await git(root, ["init", "--quiet"]);
  await git(root, ["config", "user.email", "hedge-tests@example.invalid"]);
  await git(root, ["config", "user.name", "Hedge Tests"]);
  await mkdir(join(root, "app/api/health"), { recursive: true });
  await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { next: "15.0.0" } }));
  await writeFile(
    join(root, "app/api/health/route.ts"),
    "export function GET() { return Response.json({ ok: true }); }\n"
  );
  const sha = await commitAll(root, "healthy");
  const config = parseConfigText("framework: nextjs\n");
  const context = HedgeContextSchema.parse({});
  const result = await checkHedge({
    root,
    config,
    context,
    repository: "example/repository",
    baseRevision: sha,
    headRevision: sha,
    baselineRegister: emptyRegister()
  });
  const paths = resolveStagePaths(root);
  await writeCollectionStage({
    paths,
    result,
    config,
    context,
    register: emptyRegister(),
    patch: "",
    repository: "example/repository",
    pullRequest: 17,
    baseSha: sha,
    headSha: sha
  });
  return { root, sha, paths };
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
