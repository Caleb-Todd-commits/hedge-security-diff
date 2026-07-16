import { cp, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { z } from "zod";
import { checkHedge } from "../core/run.js";
import {
  AnalysisResultSchema,
  HedgeConfigSchema,
  RiskFindingSchema,
  type AnalysisResult,
  type HedgeConfig
} from "../domain/schemas.js";
import { buildAttackSurfaceGraph } from "../analyzers/build-graph.js";
import { emptyRegister } from "../register/store.js";
import { fileExists, readJsonFile, writeJsonFile } from "../utils/fs.js";
import { loadConfig } from "../config/load.js";
import { TriageResultSchema } from "../model/schemas.js";
import type { ModelRunResult, TriageRunResult } from "../model/client.js";

const ModelUsageSchema = z.object({
  inputTokens: z.number().int().nonnegative().optional(),
  outputTokens: z.number().int().nonnegative().optional(),
  totalTokens: z.number().int().nonnegative().optional(),
  cachedInputTokens: z.number().int().nonnegative().optional(),
  reasoningTokens: z.number().int().nonnegative().optional(),
  modelCalls: z.number().int().nonnegative().optional()
});

const ReplayManifestSchema = z.object({
  schemaVersion: z.literal("0.1"),
  name: z.string().min(1),
  repository: z.string().default("hedge/replay"),
  config: HedgeConfigSchema.optional(),
  patchFile: z.string().default("patch.diff"),
  expected: z
    .object({
      surfaceChanged: z.boolean().optional(),
      decision: z.enum(["allow", "warn", "block", "accept", "verify"]).optional(),
      minFindings: z.number().int().nonnegative().optional(),
      findingTitlesInclude: z.array(z.string()).default([]),
      observationKindsInclude: z.array(z.string()).default([]),
      invariantStatuses: z.record(z.string(), z.string()).default({})
    })
    .default({ findingTitlesInclude: [], observationKindsInclude: [], invariantStatuses: {} })
});

const TriageRunSchema = z.object({
  result: TriageResultSchema,
  model: z.string(),
  usage: ModelUsageSchema.optional()
});

const ModelRunSchema = z.object({
  findings: z.array(RiskFindingSchema),
  summary: z.string(),
  limitations: z.array(z.string()),
  model: z.string(),
  integrity: z.object({
    untrustedInstructionsObserved: z.boolean(),
    analysisBoundaryHeld: z.boolean(),
    notes: z.array(z.string())
  }),
  usage: ModelUsageSchema.optional()
});

export interface ReplayResult {
  name: string;
  fixture: string;
  passed: boolean;
  failures: string[];
  analysis: AnalysisResult;
  surfaceChanged: boolean;
  findingCount: number;
  outputDirectory?: string;
}

export async function runReplay(
  fixturePath: string,
  outputDirectory?: string
): Promise<ReplayResult> {
  const fixture = resolve(fixturePath);
  const manifest = ReplayManifestSchema.parse(
    await readJsonFile<unknown>(join(fixture, "replay.json"))
  );
  const baseRoot = join(fixture, "base");
  const headRoot = join(fixture, "head");
  if (!(await directoryExists(baseRoot))) {
    throw new Error(`Replay fixture ${manifest.name} is missing base/.`);
  }
  if (!(await directoryExists(headRoot))) {
    throw new Error(`Replay fixture ${manifest.name} is missing head/.`);
  }

  const workspace = await mkdtemp(join(tmpdir(), "hedge-replay-"));
  try {
    await cp(headRoot, workspace, { recursive: true, force: true });
    const config = await replayConfig(fixture, manifest.config);
    const baselineGraph = await buildAttackSurfaceGraph({
      root: baseRoot,
      config,
      repository: manifest.repository
    });
    const baselineRegister = emptyRegister();
    baselineRegister.graph = baselineGraph;
    const patchPath = join(fixture, manifest.patchFile);
    const patch = (await fileExists(patchPath)) ? await readFile(patchPath, "utf8") : "";
    const recordedModel = await loadRecordedModel(fixture);

    const result = await checkHedge({
      root: workspace,
      config,
      patch,
      repository: manifest.repository,
      baselineRegister,
      recordedModel,
      persist: false,
      sourceCommit: `replay:${manifest.name}`
    });

    const failures = validateExpected(manifest.expected, result.analysis, result.surfaceChanged);
    let writtenOutput: string | undefined;
    if (outputDirectory) {
      writtenOutput = resolve(outputDirectory);
      await rm(writtenOutput, { recursive: true, force: true });
      await cp(join(workspace, ".hedge"), writtenOutput, { recursive: true, force: true });
      await writeJsonFile(join(writtenOutput, "replay-result.json"), {
        schemaVersion: "0.1",
        name: manifest.name,
        passed: failures.length === 0,
        failures,
        analysis: result.analysis,
        surfaceChanged: result.surfaceChanged,
        findings: result.findings
      });
    }

    return {
      name: manifest.name,
      fixture,
      passed: failures.length === 0,
      failures,
      analysis: result.analysis,
      surfaceChanged: result.surfaceChanged,
      findingCount: result.findings.length,
      ...(writtenOutput ? { outputDirectory: writtenOutput } : {})
    };
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

function validateExpected(
  expected: z.infer<typeof ReplayManifestSchema>["expected"],
  analysis: AnalysisResult,
  surfaceChanged: boolean
): string[] {
  const failures: string[] = [];
  if (expected.surfaceChanged !== undefined && expected.surfaceChanged !== surfaceChanged) {
    failures.push(
      `Expected surfaceChanged=${expected.surfaceChanged}, received ${surfaceChanged}.`
    );
  }
  const overall = analysis.decisions?.find((decision) => decision.source === "threshold");
  if (expected.decision && overall?.type !== expected.decision) {
    failures.push(`Expected decision ${expected.decision}, received ${overall?.type ?? "none"}.`);
  }
  if (expected.minFindings !== undefined && analysis.findings.length < expected.minFindings) {
    failures.push(
      `Expected at least ${expected.minFindings} finding(s), received ${analysis.findings.length}.`
    );
  }
  for (const title of expected.findingTitlesInclude) {
    if (!analysis.findings.some((finding) => finding.title.includes(title))) {
      failures.push(`Expected a finding title containing ${JSON.stringify(title)}.`);
    }
  }
  for (const kind of expected.observationKindsInclude) {
    if (!analysis.observations?.some((observation) => observation.kind === kind)) {
      failures.push(`Expected observation kind ${JSON.stringify(kind)}.`);
    }
  }
  for (const [id, status] of Object.entries(expected.invariantStatuses)) {
    const evaluation = analysis.invariantEvaluations?.find((item) => item.invariantId === id);
    if (evaluation?.status !== status) {
      failures.push(
        `Expected invariant ${id}=${status}, received ${evaluation?.status ?? "none"}.`
      );
    }
  }
  return failures;
}

async function replayConfig(
  fixture: string,
  inlineConfig: HedgeConfig | undefined
): Promise<HedgeConfig> {
  if (inlineConfig) return HedgeConfigSchema.parse(inlineConfig);
  return loadConfig(fixture, ".hedge.yml");
}

async function loadRecordedModel(
  fixture: string
): Promise<{ triage?: TriageRunResult; analysis?: ModelRunResult } | undefined> {
  const triagePath = join(fixture, "model", "triage.json");
  const analysisPath = join(fixture, "model", "analysis.json");
  const triage = (await fileExists(triagePath))
    ? TriageRunSchema.parse(await readJsonFile<unknown>(triagePath))
    : undefined;
  const analysis = (await fileExists(analysisPath))
    ? ModelRunSchema.parse(await readJsonFile<unknown>(analysisPath))
    : undefined;
  return triage || analysis ? { triage, analysis } : undefined;
}

async function directoryExists(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}
