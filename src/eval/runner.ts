import { readdir } from "node:fs/promises";
import { basename, join } from "node:path";
import { buildAttackSurfaceGraph } from "../analyzers/build-graph.js";
import { HedgeConfigSchema } from "../domain/schemas.js";
import { diffGraphs, hasSecurityArchitectureDelta } from "../graph/diff.js";
import { analyzeWithHeuristics } from "../analysis/heuristics.js";
import { readJsonFile } from "../utils/fs.js";

export interface EvalExpectation {
  framework?: "nextjs" | "express" | "auto";
  surfaceChanged: boolean;
  minimumFindings?: number;
  maximumFindings?: number;
  expectedSeverities?: string[];
  expectedTitlesContain?: string[];
  forbiddenTitlesContain?: string[];
}

export interface EvalCaseResult {
  name: string;
  passed: boolean;
  stable: boolean;
  expected: EvalExpectation;
  actual: {
    surfaceChanged: boolean;
    findings: number;
    severities: string[];
    titles: string[];
  };
  errors: string[];
}

export interface EvalSummary {
  total: number;
  passed: number;
  failed: number;
  benignSilenceRate: number;
  surfaceChangeRecall: number;
  expectedFindingRecall: number;
  countWithinExpectedRangeRate: number;
  deterministicStabilityRate: number;
  cases: EvalCaseResult[];
}

export async function runEvalSuite(fixturesRoot: string): Promise<EvalSummary> {
  const entries = (await readdir(fixturesRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const cases: EvalCaseResult[] = [];
  let expectedFragments = 0;
  let matchedFragments = 0;

  for (const entry of entries) {
    const caseRoot = join(fixturesRoot, entry);
    const expectation = await readJsonFile<EvalExpectation>(join(caseRoot, "expected.json"));
    const config = HedgeConfigSchema.parse({
      framework: expectation.framework ?? "nextjs",
      fail_on: "high"
    });
    const first = await evaluateCase(caseRoot, entry, config);
    const second = await evaluateCase(caseRoot, entry, config);
    const stable = JSON.stringify(normalize(first)) === JSON.stringify(normalize(second));
    const { surfaceChanged, findings } = first;
    const errors: string[] = [];

    if (!stable)
      errors.push("deterministic extraction or heuristic output changed across repeated runs");
    if (surfaceChanged !== expectation.surfaceChanged) {
      errors.push(
        `surfaceChanged expected ${expectation.surfaceChanged} but received ${surfaceChanged}`
      );
    }
    if (
      expectation.minimumFindings !== undefined &&
      findings.length < expectation.minimumFindings
    ) {
      errors.push(
        `expected at least ${expectation.minimumFindings} finding(s), received ${findings.length}`
      );
    }
    if (
      expectation.maximumFindings !== undefined &&
      findings.length > expectation.maximumFindings
    ) {
      errors.push(
        `expected at most ${expectation.maximumFindings} finding(s), received ${findings.length}`
      );
    }
    for (const severity of expectation.expectedSeverities ?? []) {
      if (!findings.some((finding) => finding.severity === severity))
        errors.push(`missing expected severity ${severity}`);
    }
    for (const fragment of expectation.expectedTitlesContain ?? []) {
      expectedFragments += 1;
      if (findings.some((finding) => includesIgnoreCase(finding.title, fragment))) {
        matchedFragments += 1;
      } else {
        errors.push(`no finding title contained ${JSON.stringify(fragment)}`);
      }
    }
    for (const fragment of expectation.forbiddenTitlesContain ?? []) {
      if (findings.some((finding) => includesIgnoreCase(finding.title, fragment))) {
        errors.push(`a finding title unexpectedly contained ${JSON.stringify(fragment)}`);
      }
    }

    cases.push({
      name: basename(caseRoot),
      passed: errors.length === 0,
      stable,
      expected: expectation,
      actual: {
        surfaceChanged,
        findings: findings.length,
        severities: findings.map((finding) => finding.severity),
        titles: findings.map((finding) => finding.title)
      },
      errors
    });
  }

  const benign = cases.filter((item) => !item.expected.surfaceChanged);
  const positive = cases.filter((item) => item.expected.surfaceChanged);
  const countInRange = cases.filter((item) => {
    const min = item.expected.minimumFindings ?? 0;
    const max = item.expected.maximumFindings ?? Number.POSITIVE_INFINITY;
    return item.actual.findings >= min && item.actual.findings <= max;
  });
  return {
    total: cases.length,
    passed: cases.filter((item) => item.passed).length,
    failed: cases.filter((item) => !item.passed).length,
    benignSilenceRate: benign.length
      ? benign.filter((item) => !item.actual.surfaceChanged && item.actual.findings === 0).length /
        benign.length
      : 1,
    surfaceChangeRecall: positive.length
      ? positive.filter((item) => item.actual.surfaceChanged).length / positive.length
      : 1,
    expectedFindingRecall: expectedFragments ? matchedFragments / expectedFragments : 1,
    countWithinExpectedRangeRate: cases.length ? countInRange.length / cases.length : 1,
    deterministicStabilityRate: cases.length
      ? cases.filter((item) => item.stable).length / cases.length
      : 1,
    cases
  };
}

async function evaluateCase(
  caseRoot: string,
  entry: string,
  config: ReturnType<typeof HedgeConfigSchema.parse>
) {
  const before = await buildAttackSurfaceGraph({
    root: join(caseRoot, "before"),
    config,
    repository: `eval/${entry}/before`
  });
  const after = await buildAttackSurfaceGraph({
    root: join(caseRoot, "after"),
    config,
    repository: `eval/${entry}/after`
  });
  const delta = diffGraphs(before, after);
  return {
    surfaceChanged: hasSecurityArchitectureDelta(delta),
    findings: analyzeWithHeuristics(delta, after)
  };
}

function normalize(result: Awaited<ReturnType<typeof evaluateCase>>) {
  return {
    surfaceChanged: result.surfaceChanged,
    findings: result.findings.map((finding) => ({
      fingerprint: finding.fingerprint,
      title: finding.title,
      severity: finding.severity,
      evidence: finding.evidence.map((item) => `${item.file}:${item.line ?? ""}`)
    }))
  };
}

function includesIgnoreCase(value: string, fragment: string): boolean {
  return value.toLowerCase().includes(fragment.toLowerCase());
}

export function renderEvalSummary(summary: EvalSummary): string {
  const rows = summary.cases.map(
    (item) =>
      `| ${item.passed ? "PASS" : "FAIL"} | ${item.name} | ${item.actual.surfaceChanged} | ${item.actual.findings} | ${item.stable ? "yes" : "no"} | ${item.errors.join("; ") || "—"} |`
  );
  return [
    "# Hedge evaluation results",
    "",
    `- Cases: ${summary.total}`,
    `- Passed: ${summary.passed}`,
    `- Failed: ${summary.failed}`,
    `- Benign silence rate: ${(summary.benignSilenceRate * 100).toFixed(1)}%`,
    `- Surface-change recall: ${(summary.surfaceChangeRecall * 100).toFixed(1)}%`,
    `- Expected-finding recall: ${(summary.expectedFindingRecall * 100).toFixed(1)}%`,
    `- Finding-count expectation rate: ${(summary.countWithinExpectedRangeRate * 100).toFixed(1)}%`,
    `- Deterministic stability rate: ${(summary.deterministicStabilityRate * 100).toFixed(1)}%`,
    "",
    "| Result | Case | Surface changed | Findings | Stable | Notes |",
    "|---|---|---:|---:|---:|---|",
    ...rows,
    "",
    "> These results measure the included deterministic extraction and heuristic fixtures only. They are not a claim of general vulnerability-detection accuracy. GPT-5.6 precision, stability, cost, and latency require separate repeated API-backed evaluation."
  ].join("\n");
}
