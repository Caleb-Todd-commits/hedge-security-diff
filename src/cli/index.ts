#!/usr/bin/env node
import { Command } from "commander";
import { HEDGE_VERSION } from "../version.js";
import { relative, resolve, sep } from "node:path";
import { loadConfig } from "../config/load.js";
import { checkHedge, initializeHedge } from "../core/run.js";
import { getGitDiff } from "../git/diff.js";
import {
  acceptRisk,
  loadThreatRegister,
  recordVerification,
  requireFinding,
  saveThreatRegister
} from "../register/store.js";
import { createRemediationPlan, renderRemediationPrompt } from "../remediation/plan.js";
import { runEvalSuite, renderEvalSummary } from "../eval/runner.js";
import { fileExists, readJsonFile, writeJsonFile, writeTextFile } from "../utils/fs.js";
import { renderThreatModelDocument } from "../report/threatmodel.js";
import { VerificationEvidenceSchema, type HedgeContext } from "../domain/schemas.js";
import { loadHedgeContext, saveHedgeContext } from "../config/context.js";
import { createInterface } from "node:readline/promises";
import { installHedge } from "../setup/install.js";
import { renderDoctor, runDoctor } from "../setup/doctor.js";
import { createProofBundle, verifyProofBundle } from "../report/bundle.js";
import {
  materializeSuggestedTest,
  renderFindingExplanation,
  renderRunHistory
} from "../report/finding.js";
import { runReplay } from "../replay/runner.js";

const program = new Command();
program
  .name("hedge")
  .description("Evidence-linked security architecture diffs for pull requests.")
  .version(HEDGE_VERSION);

program
  .command("install")
  .description("Install Hedge configuration and GitHub workflows into a repository.")
  .requiredOption("--action-ref <owner/repo@ref>", "published Hedge action reference")
  .option("-r, --root <path>", "repository root", ".")
  .option("--full", "install remediation, verification, refresh, and prune workflows", false)
  .option("--force", "overwrite existing Hedge files", false)
  .action(async (options: { actionRef: string; root: string; full: boolean; force: boolean }) => {
    const result = await installHedge({
      root: resolve(options.root),
      actionRef: options.actionRef,
      full: options.full,
      force: options.force
    });
    console.log(`Installed ${result.written.length} Hedge file(s).`);
    for (const path of result.written) console.log(`+ ${path}`);
    for (const path of result.skipped) console.log(`= ${path} (already exists)`);
    console.log(
      "Next: run hedge init --configure, add OPENAI_API_KEY, and commit the generated baseline."
    );
  });

program
  .command("doctor")
  .description("Validate the local Hedge installation, baseline, and workflow posture.")
  .option("-r, --root <path>", "repository root", ".")
  .option("--json <path>", "write the diagnostic result as JSON")
  .action(async (options: { root: string; json?: string }) => {
    const result = await runDoctor(resolve(options.root));
    if (options.json) await writeJsonFile(resolve(options.json), result);
    console.log(renderDoctor(result));
    if (!result.healthy) process.exitCode = 1;
  });

program
  .command("explain")
  .description("Explain one recorded Hedge risk with its evidence and lifecycle state.")
  .argument("<risk-id>")
  .option("-r, --root <path>", "repository root", ".")
  .action(async (riskId: string, options: { root: string }) => {
    const register = await loadThreatRegister(resolve(options.root));
    console.log(renderFindingExplanation(register, riskId));
  });

program
  .command("history")
  .description("Show the latest persisted Hedge architecture and risk runs.")
  .option("-r, --root <path>", "repository root", ".")
  .action(async (options: { root: string }) => {
    const register = await loadThreatRegister(resolve(options.root));
    console.log(renderRunHistory(register));
  });

program
  .command("witness")
  .description("Materialize a finding's suggested security witness as a reviewable test file.")
  .argument("<risk-id>")
  .option("-r, --root <path>", "repository root", ".")
  .option("-o, --output <path>", "repository-relative output path")
  .option("--force", "overwrite an existing witness file", false)
  .action(async (riskId: string, options: { root: string; output?: string; force: boolean }) => {
    const root = resolve(options.root);
    const register = await loadThreatRegister(root);
    const finding = requireFinding(register, riskId);
    const witness = materializeSuggestedTest(finding, options.output);
    const output = resolve(root, witness.relativePath);
    const relativeOutput = relative(root, output);
    if (relativeOutput.startsWith(`..${sep}`) || relativeOutput === "..") {
      throw new Error("Witness output must remain inside the repository root.");
    }
    if (!options.force && (await fileExists(output))) {
      throw new Error(`${relativeOutput} already exists; pass --force to replace it.`);
    }
    await writeTextFile(output, witness.content);
    console.log(`Wrote ${relativeOutput}.`);
    console.log(
      "Next: prove this witness succeeds on the vulnerable revision and is blocked after remediation."
    );
  });

program
  .command("bundle")
  .description("Create a tamper-evident proof bundle from Hedge reports and state.")
  .option("-r, --root <path>", "repository root", ".")
  .option("-o, --output <path>", "repository-relative bundle directory", ".hedge/proof")
  .option("--repository <name>", "repository label")
  .option("--base <ref>", "base revision label")
  .option("--head <ref>", "head revision label")
  .action(
    async (options: {
      root: string;
      output: string;
      repository?: string;
      base?: string;
      head?: string;
    }) => {
      const root = resolve(options.root);
      const output = resolve(root, options.output);
      const relativeOutput = relative(root, output);
      if (relativeOutput.startsWith(`..${sep}`) || relativeOutput === "..") {
        throw new Error("Proof bundle output must remain inside the repository root.");
      }
      const result = await createProofBundle({
        root,
        output: relativeOutput,
        repository: options.repository,
        baseRef: options.base,
        headRef: options.head
      });
      console.log(`Wrote proof bundle ${relative(root, result.directory)}.`);
      console.log(`Manifest digest: ${result.manifest.manifestDigest}`);
    }
  );

program
  .command("verify-bundle")
  .description("Verify the digest manifest and copied artifacts in a Hedge proof bundle.")
  .argument("<manifest>")
  .action(async (manifest: string) => {
    const warnings = await verifyProofBundle(resolve(manifest));
    if (warnings.length) {
      for (const warning of warnings) console.error(`FAIL ${warning}`);
      process.exitCode = 1;
      return;
    }
    console.log("Proof bundle integrity verified.");
  });

program
  .command("init")
  .description("Create or refresh THREATMODEL.md and threatmodel.json from repository evidence.")
  .option("-r, --root <path>", "repository root", ".")
  .option("-c, --config <path>", "configuration path", ".hedge.yml")
  .option("--configure", "ask the five high-value threat-context questions", false)
  .action(async (options: { root: string; config: string; configure: boolean }) => {
    const root = resolve(options.root);
    if (options.configure) await configureContextInteractively(root);
    const config = await loadConfig(root, options.config);
    const result = await initializeHedge(root, config);
    console.log(
      `Hedge initialized ${result.graph.nodes.length} nodes and ${result.graph.edges.length} edges.`
    );
    console.log(`Wrote ${result.threatModelPath}`);
    console.log(`Wrote ${result.statePath}`);
  });

program
  .command("context")
  .description("Create or update the five reviewed facts source code cannot reliably infer.")
  .option("-r, --root <path>", "repository root", ".")
  .option("--template", "write an empty reviewed context template without prompting", false)
  .action(async (options: { root: string; template: boolean }) => {
    const root = resolve(options.root);
    if (options.template) {
      const path = await saveHedgeContext(root, await loadHedgeContext(root));
      console.log(`Wrote ${path}`);
      return;
    }
    await configureContextInteractively(root);
  });

program
  .command("check")
  .description("Compare the current repository to the stored Hedge baseline.")
  .option("-r, --root <path>", "repository root", ".")
  .option("-c, --config <path>", "configuration path", ".hedge.yml")
  .option("--base <ref>", "base git ref", "HEAD~1")
  .option("--head <ref>", "head git ref", "HEAD")
  .option("--persist", "persist the current graph and findings after checking", false)
  .option("--offline", "skip GPT-5.6 even if OPENAI_API_KEY is set", false)
  .option("--json <path>", "write a machine-readable run result")
  .action(
    async (options: {
      root: string;
      config: string;
      base: string;
      head: string;
      persist: boolean;
      offline: boolean;
      json?: string;
    }) => {
      const root = resolve(options.root);
      const config = await loadConfig(root, options.config);
      let patch = "";
      try {
        patch = (await getGitDiff(root, options.base, options.head, config.limits.max_bytes)).patch;
      } catch (error) {
        console.warn(`Could not read git diff: ${(error as Error).message}`);
      }
      const result = await checkHedge({
        root,
        config,
        patch,
        apiKey: options.offline ? undefined : process.env.OPENAI_API_KEY,
        persist: options.persist
      });
      console.log(
        result.surfaceChanged
          ? result.report
          : "No security architecture delta. No model call made."
      );
      console.log(`\nHTML dashboard: ${result.htmlReportPath}`);
      console.log(`SARIF report: ${result.sarifPath}`);
      console.log(`Architecture delta: ${result.deltaPath}`);
      console.log(`Analysis JSON: ${result.analysisPath}`);
      if (options.json) {
        await writeJsonFile(resolve(options.json), {
          surfaceChanged: result.surfaceChanged,
          findings: result.findings,
          lifecycleUpdates: result.lifecycleUpdates,
          delta: result.delta,
          analysis: result.analysis
        });
      }
    }
  );

program
  .command("fix-plan")
  .description("Generate the approval-gated Codex handoff for a recorded Hedge risk.")
  .argument("<risk-id>")
  .option("-r, --root <path>", "repository root", ".")
  .option("-o, --output <path>", "write the Codex prompt to a file")
  .option("--json <path>", "write the complete remediation plan as JSON")
  .action(async (riskId: string, options: { root: string; output?: string; json?: string }) => {
    const root = resolve(options.root);
    const register = await loadThreatRegister(root);
    const finding = requireFinding(register, riskId);
    const plan = createRemediationPlan(finding);
    const prompt = renderRemediationPrompt(plan);
    if (options.output) await writeTextFile(resolve(options.output), prompt);
    if (options.json) await writeJsonFile(resolve(options.json), plan);
    if (!options.output && !options.json) console.log(JSON.stringify(plan, null, 2));
  });

program
  .command("prune")
  .alias("accept")
  .description("Record a deliberate risk acceptance with actor, time, and reason.")
  .argument("<risk-id>")
  .requiredOption("--reason <text>", "why the risk is accepted")
  .option("--actor <name>", "person accepting the risk", process.env.GITHUB_ACTOR ?? "local-user")
  .option("-r, --root <path>", "repository root", ".")
  .action(async (riskId: string, options: { reason: string; actor: string; root: string }) => {
    const root = resolve(options.root);
    const register = await loadThreatRegister(root);
    const finding = acceptRisk(register, riskId, options.reason, options.actor);
    await persistRegisterDocuments(root, register);
    console.log(`${finding.id} accepted by ${options.actor}: ${options.reason}`);
  });

program
  .command("verify")
  .description("Record counterfactual verification evidence for a Hedge risk.")
  .argument("<risk-id>")
  .requiredOption("--evidence <path>", "JSON file matching the verification evidence schema")
  .option("--actor <name>", "verification recorder", process.env.GITHUB_ACTOR ?? "local-user")
  .option("-r, --root <path>", "repository root", ".")
  .action(async (riskId: string, options: { evidence: string; actor: string; root: string }) => {
    const root = resolve(options.root);
    const raw = await readJsonFile<unknown>(resolve(options.evidence));
    const evidence = VerificationEvidenceSchema.parse({
      ...(raw as Record<string, unknown>),
      recordedBy: options.actor
    });
    const register = await loadThreatRegister(root);
    const finding = recordVerification(register, riskId, evidence);
    await persistRegisterDocuments(root, register);
    console.log(`${finding.id} is now ${finding.status}.`);
  });

program
  .command("status")
  .description("Show the current risk register grouped by lifecycle state.")
  .option("-r, --root <path>", "repository root", ".")
  .action(async (options: { root: string }) => {
    const register = await loadThreatRegister(resolve(options.root));
    const grouped = new Map<string, typeof register.findings>();
    for (const finding of register.findings) {
      const bucket = grouped.get(finding.status) ?? [];
      bucket.push(finding);
      grouped.set(finding.status, bucket);
    }
    for (const status of [
      "open",
      "mitigation-detected",
      "verification-available",
      "verified",
      "accepted",
      "closed"
    ]) {
      const findings = grouped.get(status) ?? [];
      console.log(`\n${status.toUpperCase()} (${findings.length})`);
      for (const finding of findings) {
        console.log(`- ${finding.id} [${finding.severity}] ${finding.title}`);
      }
    }
  });

program
  .command("replay")
  .description("Replay a complete Hedge run from a versioned base/head fixture.")
  .argument("<fixture>", "replay fixture containing replay.json, base/, and head/")
  .option("-o, --output <path>", "copy replay artifacts to this directory")
  .action(async (fixture: string, options: { output?: string }) => {
    const result = await runReplay(
      resolve(fixture),
      options.output ? resolve(options.output) : undefined
    );
    console.log(`${result.passed ? "PASS" : "FAIL"} ${result.name}`);
    console.log(`Surface changed: ${result.surfaceChanged ? "yes" : "no"}`);
    console.log(`Findings: ${result.findingCount}`);
    const decision = result.analysis.decisions?.find((item) => item.source === "threshold");
    console.log(`Decision: ${decision?.type ?? "none"}`);
    if (result.outputDirectory) console.log(`Artifacts: ${result.outputDirectory}`);
    for (const failure of result.failures) console.error(`- ${failure}`);
    if (!result.passed) process.exitCode = 1;
  });

program
  .command("eval")
  .description("Run the deterministic DriftBench fixtures.")
  .option("-f, --fixtures <path>", "fixture directory", "eval/fixtures")
  .option("--no-write", "print results without changing eval/results files")
  .action(async (options: { fixtures: string; write?: boolean }) => {
    const summary = await runEvalSuite(resolve(options.fixtures));
    if (options.write !== false) {
      await writeTextFile(resolve("eval/results.md"), renderEvalSummary(summary));
      await writeJsonFile(resolve("eval/results.json"), summary);
    }
    console.log(renderEvalSummary(summary));
    if (summary.failed) process.exitCode = 1;
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

async function persistRegisterDocuments(
  root: string,
  register: Awaited<ReturnType<typeof loadThreatRegister>>
): Promise<void> {
  await saveThreatRegister(root, register);
  if (register.graph) {
    await writeTextFile(
      resolve(root, "THREATMODEL.md"),
      renderThreatModelDocument(register.graph, register)
    );
  }
}

async function configureContextInteractively(root: string): Promise<void> {
  if (!process.stdin.isTTY) {
    const path = await saveHedgeContext(root, await loadHedgeContext(root));
    console.log(`No interactive terminal detected; wrote context template ${path}`);
    return;
  }
  const current = await loadHedgeContext(root);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const context: HedgeContext = {
      sensitive_assets: await askList(
        rl,
        "Which data or assets are most sensitive?",
        current.sensitive_assets
      ),
      internet_facing: await askList(
        rl,
        "Which components are internet-facing?",
        current.internet_facing
      ),
      authentication: await askList(
        rl,
        "What authenticates users and services?",
        current.authentication
      ),
      privileged_roles: await askList(
        rl,
        "Which roles have privileged access?",
        current.privileged_roles
      ),
      trusted_external_services: await askList(
        rl,
        "Which external services are explicitly trusted?",
        current.trusted_external_services
      ),
      notes: current.notes
    };
    const path = await saveHedgeContext(root, context);
    console.log(`Wrote reviewed threat context to ${path}`);
  } finally {
    rl.close();
  }
}

async function askList(
  rl: ReturnType<typeof createInterface>,
  question: string,
  current: string[]
): Promise<string[]> {
  const suffix = current.length ? ` [${current.join(", ")}]` : "";
  const answer = (await rl.question(`${question}${suffix}\n> `)).trim();
  if (!answer) return current;
  return answer
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}
