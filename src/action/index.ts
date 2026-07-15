import * as core from "@actions/core";
import * as github from "@actions/github";
import { resolve } from "node:path";
import { loadConfig } from "../config/load.js";
import { checkHedge, initializeHedge } from "../core/run.js";
import { getGitDiff } from "../git/diff.js";
import { upsertPullRequestComment } from "../github/comment.js";
import { loadTrustedPullRequestState } from "../github/content.js";
import {
  acceptRisk,
  emptyRegister,
  loadThreatRegister,
  recordVerification,
  saveThreatRegister
} from "../register/store.js";
import {
  VerificationEvidenceSchema,
  type HedgeConfig,
  type HedgeContext,
  type Severity,
  type ThreatRegister
} from "../domain/schemas.js";
import { createFindingAnnotations } from "../github/annotations.js";
import { readJsonFile, writeTextFile } from "../utils/fs.js";
import { renderThreatModelDocument } from "../report/threatmodel.js";
import { isUnresolvedRisk } from "../register/status.js";

async function main(): Promise<void> {
  const root = resolve(core.getInput("root") || ".");
  const configPath = core.getInput("config-path") || ".hedge.yml";
  const command = core.getInput("command") || "check";
  const dryRun = core.getBooleanInput("dry-run");
  const apiKey = core.getInput("openai-api-key") || process.env.OPENAI_API_KEY;
  const githubToken = core.getInput("github-token") || process.env.GITHUB_TOKEN;
  if (apiKey) core.setSecret(apiKey);
  if (githubToken) core.setSecret(githubToken);
  const repository = process.env.GITHUB_REPOSITORY ?? "local";
  const pullRequest = github.context.payload.pull_request;

  let config: HedgeConfig;
  let baselineRegister: ThreatRegister | undefined;
  let trustedContext: HedgeContext | undefined;
  let patch = "";

  if (pullRequest && githubToken) {
    const trusted = await loadTrustedPullRequestState({
      token: githubToken,
      baseSha: pullRequest.base.sha,
      pullNumber: pullRequest.number,
      configPath
    });
    config = trusted.config;
    baselineRegister = trusted.register ?? emptyRegister();
    trustedContext = trusted.context;
    patch = trusted.patch;
    for (const warning of trusted.warnings) core.warning(warning);
    if (trusted.patchTruncated) {
      core.warning(
        "GitHub PR patch evidence was truncated to the trusted base configuration budget."
      );
    }
  } else {
    config = await loadConfig(root, configPath);
  }

  // Explicit workflow inputs are trusted workflow configuration and may override
  // the repository config. PR source content cannot override these values.
  config.models.triage = core.getInput("model-triage") || config.models.triage;
  config.models.analysis = core.getInput("model-analysis") || config.models.analysis;

  if (command === "verify") {
    const riskId = core.getInput("risk-id");
    const evidencePath = core.getInput("verification-evidence");
    if (!riskId || !evidencePath) {
      throw new Error("verify requires risk-id and verification-evidence inputs.");
    }
    const register = await loadThreatRegister(root);
    const raw = await readJsonFile<unknown>(resolve(root, evidencePath));
    const architectureOverride = core.getInput("architecture-control-changed");
    const evidence = VerificationEvidenceSchema.parse({
      ...(raw as Record<string, unknown>),
      ...(architectureOverride
        ? { architectureControlChanged: architectureOverride.toLowerCase() === "true" }
        : {}),
      recordedBy: core.getInput("actor") || process.env.GITHUB_ACTOR || "github-actions"
    });
    const finding = recordVerification(register, riskId, evidence);
    await persistRegisterDocuments(root, register);
    core.setOutput("surface-changed", "false");
    core.setOutput("open-risks", String(register.findings.filter(isUnresolvedRisk).length));
    core.setOutput(
      "highest-severity",
      highestSeverity(register.findings.filter(isUnresolvedRisk).map((item) => item.severity))
    );
    core.setOutput("decision", register.findings.some(isUnresolvedRisk) ? "warn" : "allow");
    core.setOutput("report-path", resolve(root, "THREATMODEL.md"));
    core.setOutput("html-report-path", "");
    core.setOutput("sarif-path", "");
    core.setOutput("delta-path", "");
    core.setOutput("analysis-path", "");
    core.info(`${finding.id} is now ${finding.status}.`);
    return;
  }

  if (command === "prune") {
    const riskId = core.getInput("risk-id");
    const encodedReason = core.getInput("acceptance-reason-b64");
    const reason = encodedReason
      ? decodeBase64Input(encodedReason, "acceptance-reason-b64")
      : core.getInput("acceptance-reason");
    if (!riskId || !reason) {
      throw new Error(
        "prune requires risk-id and acceptance-reason or acceptance-reason-b64 inputs."
      );
    }
    const actor = core.getInput("actor") || process.env.GITHUB_ACTOR || "github-actions";
    const register = await loadThreatRegister(root);
    const finding = acceptRisk(register, riskId, reason, actor);
    await persistRegisterDocuments(root, register);
    core.setOutput("surface-changed", "false");
    core.setOutput("open-risks", String(register.findings.filter(isUnresolvedRisk).length));
    core.setOutput(
      "highest-severity",
      highestSeverity(register.findings.filter(isUnresolvedRisk).map((item) => item.severity))
    );
    core.setOutput("decision", register.findings.some(isUnresolvedRisk) ? "warn" : "allow");
    core.setOutput("report-path", resolve(root, "THREATMODEL.md"));
    core.setOutput("html-report-path", "");
    core.setOutput("sarif-path", "");
    core.setOutput("delta-path", "");
    core.setOutput("analysis-path", "");
    core.info(`${finding.id} accepted by ${actor}.`);
    return;
  }

  if (command === "init") {
    const result = await initializeHedge(root, config, repository);
    core.info(
      `Hedge initialized ${result.graph.nodes.length} nodes and ${result.graph.edges.length} edges.`
    );
    core.setOutput("surface-changed", "true");
    const unresolved = result.register.findings.filter(isUnresolvedRisk);
    core.setOutput("open-risks", unresolved.length);
    core.setOutput("highest-severity", highestSeverity(unresolved.map((item) => item.severity)));
    core.setOutput("decision", unresolved.length ? "warn" : "allow");
    core.setOutput("report-path", result.threatModelPath);
    core.setOutput("html-report-path", "");
    core.setOutput("sarif-path", "");
    core.setOutput("delta-path", "");
    core.setOutput("analysis-path", "");
    return;
  }

  if (pullRequest && !patch) {
    try {
      const diff = await getGitDiff(
        root,
        pullRequest.base.sha,
        pullRequest.head.sha,
        config.limits.max_bytes
      );
      patch = diff.patch;
      if (diff.truncated) core.warning("Git diff was truncated to the configured byte budget.");
    } catch (error) {
      core.warning(
        `Unable to read git diff; continuing with graph evidence only: ${(error as Error).message}`
      );
    }
  }

  const result = await checkHedge({
    root,
    config,
    patch,
    apiKey,
    repository,
    persist: false,
    baselineRegister,
    context: trustedContext,
    sourceCommit: pullRequest?.head.sha ?? process.env.GITHUB_SHA
  });

  const openFindings = result.findings.filter(isUnresolvedRisk);
  const highest = highestSeverity(openFindings.map((finding) => finding.severity));
  const decision =
    result.analysis.decisions?.find((item) => item.source === "threshold")?.type ??
    (reachesThreshold(highest, config.fail_on) ? "block" : openFindings.length ? "warn" : "allow");
  core.setOutput("surface-changed", String(result.surfaceChanged));
  core.setOutput("open-risks", String(openFindings.length));
  core.setOutput("highest-severity", highest);
  core.setOutput("decision", decision);
  core.setOutput("report-path", result.reportPath);
  core.setOutput("html-report-path", result.htmlReportPath);
  core.setOutput("sarif-path", result.sarifPath);
  core.setOutput("delta-path", result.deltaPath);
  core.setOutput("analysis-path", result.analysisPath);

  await core.summary
    .addHeading("Hedge security diff")
    .addRaw(
      result.surfaceChanged
        ? result.analysis.summary
        : "No security architecture delta. No model call made."
    )
    .addTable([
      [
        { data: "Metric", header: true },
        { data: "Value", header: true }
      ],
      ["Architecture changed", result.surfaceChanged ? "yes" : "no"],
      ["Open findings", String(openFindings.length)],
      ["Highest severity", highest],
      ["Decision", decision],
      [
        "Explicit invariant violations",
        String(
          result.analysis.invariantEvaluations?.filter((item) => item.status === "violated")
            .length ?? 0
        )
      ],
      ["Analysis model", result.analysis.model ?? "none"]
    ])
    .addRaw(
      `
Artifacts: \`${result.reportPath}\`, \`${result.htmlReportPath}\`, \`${result.sarifPath}\``
    )
    .write();

  for (const annotation of createFindingAnnotations(openFindings)) {
    const properties = {
      title: annotation.title,
      ...(annotation.file ? { file: annotation.file } : {}),
      ...(annotation.startLine ? { startLine: annotation.startLine } : {}),
      ...(annotation.endLine ? { endLine: annotation.endLine } : {})
    };
    if (annotation.level === "error") core.error(annotation.message, properties);
    else if (annotation.level === "warning") core.warning(annotation.message, properties);
    else core.notice(annotation.message, properties);
  }

  // Silence-by-default: no PR comment when the evidence-linked surface did not change.
  if (result.surfaceChanged && githubToken && !dryRun) {
    await upsertPullRequestComment(githubToken, result.report);
  }

  if (!dryRun && decision === "block") {
    core.setFailed(
      `Hedge decision: BLOCK. ${openFindings.length} unresolved risk(s) meet the configured ${config.fail_on} threshold.`
    );
  }
}

function highestSeverity(values: Severity[]): Severity {
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  return values.reduce(
    (highest, value) => (order.indexOf(value) > order.indexOf(highest) ? value : highest),
    "info"
  );
}

function reachesThreshold(actual: Severity, threshold: Severity): boolean {
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  return order.indexOf(actual) >= order.indexOf(threshold);
}

function decodeBase64Input(value: string, name: string): string {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error(`${name} is not canonical base64.`);
  }
  const decoded = Buffer.from(value, "base64").toString("utf8");
  const canonical = Buffer.from(decoded, "utf8").toString("base64");
  if (canonical !== value) throw new Error(`${name} failed base64 validation.`);
  return decoded;
}

async function persistRegisterDocuments(root: string, register: ThreatRegister): Promise<void> {
  await saveThreatRegister(root, register);
  if (register.graph) {
    await writeTextFile(
      resolve(root, "THREATMODEL.md"),
      renderThreatModelDocument(register.graph, register)
    );
  }
}

main().catch((error: unknown) =>
  core.setFailed(error instanceof Error ? error.message : String(error))
);
