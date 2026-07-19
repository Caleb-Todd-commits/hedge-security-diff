import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";
import { loadConfig } from "../config/load.js";
import { loadHedgeContext } from "../config/context.js";
import { loadThreatRegister, validateThreatRegisterBindings } from "../register/store.js";
import { fileExists } from "../utils/fs.js";
import fg from "fast-glob";
import { buildAttackSurfaceGraph } from "../analyzers/build-graph.js";
import type { HedgeConfig } from "../domain/schemas.js";

export interface DoctorCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  detail: string;
}

export interface DoctorResult {
  healthy: boolean;
  checks: DoctorCheck[];
}

export async function runDoctor(root: string): Promise<DoctorResult> {
  const checks: DoctorCheck[] = [];
  const major = Number(process.versions.node.split(".")[0]);
  checks.push({
    name: "Node.js",
    status: major >= 22 ? "pass" : "fail",
    detail: `Node ${process.versions.node}; Hedge requires Node 22 or newer.`
  });

  const sourceMode =
    (await fileExists(resolve(root, "action.yml"))) &&
    (await fileExists(resolve(root, "src/action/index.ts")));
  checks.push(await pathCheck(root, ".git", "Git repository", sourceMode ? "warn" : "fail"));
  checks.push(await pathCheck(root, "package.json", "Package manifest", "warn"));
  checks.push(await pathCheck(root, ".hedge.yml", "Hedge configuration"));
  checks.push(await pathCheck(root, ".hedge/context.yml", "Reviewed threat context", "warn"));
  checks.push(
    await pathCheck(
      root,
      ".github/workflows/hedge.yml",
      "Pull request workflow",
      sourceMode ? "warn" : "fail"
    )
  );

  let parsedConfig: HedgeConfig | undefined;
  try {
    const config = await loadConfig(root);
    parsedConfig = config;
    checks.push({
      name: "Configuration parse",
      status: "pass",
      detail: `Framework ${config.framework}; fail threshold ${config.fail_on}; ${config.invariants.length} explicit invariant(s); ${config.limits.max_files} file budget.`
    });
  } catch (error) {
    checks.push({ name: "Configuration parse", status: "fail", detail: (error as Error).message });
  }

  if (parsedConfig) {
    try {
      const graph = await buildAttackSurfaceGraph({ root, config: parsedConfig });
      const entrypoints = graph.nodes.filter((node) => node.kind === "entrypoint").length;
      const coverage = graph.coverage?.status ?? "unsupported";
      checks.push({
        name: "Repository surface compatibility",
        status: graph.framework !== "unknown" && entrypoints > 0 ? "pass" : "warn",
        detail:
          graph.framework !== "unknown" && entrypoints > 0
            ? `Detected ${graph.framework} with ${coverage} coverage and ${entrypoints} supported entry point(s).`
            : `Detected ${graph.framework} with ${coverage} coverage and ${entrypoints} supported entry point(s); unsupported or empty surfaces produce explicit warnings rather than model guesses.`
      });
    } catch (error) {
      checks.push({
        name: "Repository surface compatibility",
        status: "warn",
        detail: `Could not inspect supported surfaces: ${(error as Error).message}`
      });
    }
  }

  try {
    const context = await loadHedgeContext(root);
    const answered = [
      context.sensitive_assets,
      context.internet_facing,
      context.authentication,
      context.privileged_roles,
      context.trusted_external_services
    ].filter((value) => value.length).length;
    checks.push({
      name: "Threat context review",
      status: answered >= 3 ? "pass" : "warn",
      detail: `${answered}/5 high-value context areas contain reviewed values.`
    });
  } catch (error) {
    checks.push({
      name: "Threat context review",
      status: "fail",
      detail: (error as Error).message
    });
  }

  if (await fileExists(resolve(root, "threatmodel.json"))) {
    try {
      const register = await loadThreatRegister(root);
      checks.push({
        name: "Baseline integrity",
        status: register.graph ? "pass" : "warn",
        detail: register.graph
          ? `${register.graph.nodes.length} nodes, ${register.graph.edges.length} edges, ${register.findings.length} recorded risks.`
          : "The register exists but has no stored graph."
      });
      if (register.stateIntegrity) {
        const currentAlgorithm =
          register.stateIntegrity.algorithm === "sha256-stable-json-v2" &&
          !register.stateIntegrity.toolVersion?.startsWith("0.4.");
        checks.push({
          name: "Integrity format",
          status: currentAlgorithm ? "pass" : "warn",
          detail: currentAlgorithm
            ? "Graph and full-register digests use the current durable hashing format."
            : "Legacy integrity is accepted for migration; run hedge init to reseal invariants and the full register with v0.5."
        });
      }
      const bindingWarnings = validateThreatRegisterBindings(register, {
        config: parsedConfig ?? (await loadConfig(root)),
        context: await loadHedgeContext(root)
      });
      checks.push({
        name: "Baseline policy binding",
        status: bindingWarnings.length ? "warn" : "pass",
        detail: bindingWarnings.length
          ? bindingWarnings.join(" ")
          : "Stored graph, policy, and reviewed-context digests agree."
      });
    } catch (error) {
      checks.push({ name: "Baseline integrity", status: "fail", detail: (error as Error).message });
    }
  } else {
    checks.push({
      name: "Baseline integrity",
      status: "warn",
      detail: "No threatmodel.json exists yet; run hedge init --configure."
    });
  }

  checks.push({
    name: "OpenAI credential",
    status: process.env.OPENAI_API_KEY ? "pass" : "warn",
    detail: process.env.OPENAI_API_KEY
      ? "OPENAI_API_KEY is available to this process."
      : "No local OPENAI_API_KEY detected; deterministic offline mode remains available."
  });

  const hedgeWorkflows = await fg(".github/workflows/hedge*.yml", {
    cwd: root,
    absolute: true,
    onlyFiles: true
  });
  const placeholderFiles: string[] = [];
  for (const workflow of hedgeWorkflows) {
    const text = await readFile(workflow, "utf8");
    if (/YOUR_ORG\/hedge@PINNED_COMMIT_SHA|PINNED_COMMIT_SHA/.test(text)) {
      placeholderFiles.push(workflow.replace(`${resolve(root)}/`, ""));
    }
  }
  checks.push({
    name: "Workflow placeholders",
    status: placeholderFiles.length ? "fail" : "pass",
    detail: placeholderFiles.length
      ? `Unresolved action placeholders remain in ${placeholderFiles.join(", ")}.`
      : "No unresolved Hedge action placeholders were found."
  });

  const workflowPath = resolve(root, ".github/workflows/hedge.yml");
  if (await fileExists(workflowPath)) {
    const workflow = await readFile(workflowPath, "utf8");
    checks.push({
      name: "Pinned action reference",
      status: /uses:\s*[^\s]+@[0-9a-f]{40}\b/i.test(workflow) ? "pass" : "warn",
      detail: /uses:\s*[^\s]+@[0-9a-f]{40}\b/i.test(workflow)
        ? "The main workflow contains an immutable commit reference."
        : "Pin the Hedge action and third-party actions to immutable commits for production."
    });
  }

  return { healthy: !checks.some((check) => check.status === "fail"), checks };
}

async function pathCheck(
  root: string,
  path: string,
  name: string,
  missingStatus: DoctorCheck["status"] = "fail"
): Promise<DoctorCheck> {
  try {
    await access(resolve(root, path), constants.R_OK);
    return { name, status: "pass", detail: `${path} is readable.` };
  } catch {
    return { name, status: missingStatus, detail: `${path} is missing or unreadable.` };
  }
}

export function renderDoctor(result: DoctorResult): string {
  const icon = { pass: "PASS", warn: "WARN", fail: "FAIL" } as const;
  return [
    "Hedge doctor",
    "",
    ...result.checks.map(
      (check) => `${icon[check.status].padEnd(4)}  ${check.name.padEnd(24)} ${check.detail}`
    ),
    "",
    result.healthy
      ? "No blocking installation failures detected."
      : "One or more blocking failures must be resolved before running Hedge."
  ].join("\n");
}
