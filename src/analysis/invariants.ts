import type {
  GraphDelta,
  InvariantEvaluation,
  RiskFinding,
  SecurityInvariantDefinition,
  SurfaceNode
} from "../domain/schemas.js";
import { stableHash } from "../utils/hash.js";

export interface InvariantAnalysis {
  evaluations: InvariantEvaluation[];
  findings: RiskFinding[];
}

export function analyzeSecurityInvariants(
  delta: GraphDelta,
  invariants: SecurityInvariantDefinition[]
): InvariantAnalysis {
  const candidates = uniqueNodes([
    ...delta.addedNodes,
    ...delta.changedNodes.map((pair) => pair.after)
  ]);
  const evaluations: InvariantEvaluation[] = [];
  const findings: RiskFinding[] = [];

  for (const invariant of invariants.filter((item) => item.enabled)) {
    const matched = candidates.filter((node) => matches(node, invariant));
    if (!matched.length) {
      evaluations.push({
        invariantId: invariant.id,
        description: invariant.description,
        severity: invariant.severity,
        status: "not-applicable",
        matchedNodeIds: [],
        missingControls: [],
        evidence: [],
        reason: "No changed architecture surface matched this invariant."
      });
      continue;
    }

    const violating = matched
      .map((node) => ({ node, missing: missingControls(node, invariant) }))
      .filter((item) => item.missing.length > 0);
    const missing = [...new Set(violating.flatMap((item) => item.missing))];
    const evidence = violating.length
      ? violating.flatMap((item) => item.node.evidence)
      : matched.flatMap((node) => node.evidence);

    if (!violating.length) {
      evaluations.push({
        invariantId: invariant.id,
        description: invariant.description,
        severity: invariant.severity,
        status: "satisfied",
        matchedNodeIds: matched.map((node) => node.id),
        missingControls: [],
        evidence,
        reason: `All ${matched.length} matching changed surface(s) contain the required controls.`
      });
      continue;
    }

    evaluations.push({
      invariantId: invariant.id,
      description: invariant.description,
      severity: invariant.severity,
      status: "violated",
      matchedNodeIds: matched.map((node) => node.id),
      missingControls: missing,
      evidence,
      reason: `${violating.length} matching changed surface(s) are missing ${missing.join(", ")}.`
    });

    for (const { node, missing: nodeMissing } of violating) {
      findings.push(invariantFinding(invariant, node, nodeMissing));
    }
  }

  return { evaluations, findings };
}

function invariantFinding(
  invariant: SecurityInvariantDefinition,
  node: SurfaceNode,
  missing: Array<SurfaceNode["controls"][number]["type"]>
): RiskFinding {
  const now = new Date().toISOString();
  return {
    id: "HEDGE-PENDING",
    fingerprint: stableHash({ invariant: invariant.id, node: node.id, missing }, 24),
    title: `${invariant.id} violated: ${missing.join(", ")} not detected`,
    severity: invariant.severity,
    origin: "invariant",
    status: "open",
    stride: [],
    cwe: [],
    asset: "Repository-defined protected behavior",
    attackerCapability: "Reach the matching changed architecture surface",
    entryPoint: node.label,
    trustBoundary: `${node.trustZone} architecture surface governed by ${invariant.id}`,
    precondition: `The changed component matches invariant ${invariant.id}.`,
    attackPath: [node.label, `Invariant ${invariant.id}`, `Missing ${missing.join(", ")}`],
    potentialImpact: invariant.rationale,
    existingControls: node.controls.map((control) => control.label),
    missingControls: missing,
    securityInvariant: invariant.description,
    evidence: node.evidence,
    confidence: 1,
    suggestedTest: {
      title: `Executable witness for ${invariant.id}`,
      framework: "vitest",
      language: "typescript",
      purpose: invariant.description,
      code: `it(${JSON.stringify(invariant.description)}, async () => {\n  // Replace this placeholder with an executable witness against ${node.label}.\n  expect.fail(${JSON.stringify(`Implement security invariant witness ${invariant.id}`)});\n});`
    },
    remediationPrompt: [
      `Restore repository security invariant ${invariant.id}.`,
      `Invariant: ${invariant.description}`,
      `Changed surface: ${node.label}`,
      `Missing controls: ${missing.join(", ")}`,
      "Make the smallest focused change and add an executable counterfactual witness."
    ].join("\n"),
    verificationHistory: [],
    createdAt: now,
    updatedAt: now
  };
}

function matches(node: SurfaceNode, invariant: SecurityInvariantDefinition): boolean {
  const match = invariant.applies_to;
  if (match.kinds.length && !match.kinds.includes(node.kind)) return false;
  if (match.trust_zones.length && !match.trust_zones.includes(node.trustZone)) return false;
  const method = String(node.metadata.method ?? "").toUpperCase();
  if (match.methods.length && !match.methods.map((value) => value.toUpperCase()).includes(method)) {
    return false;
  }
  if (match.label_pattern && !globLike(match.label_pattern, node.label)) return false;
  return true;
}

function missingControls(
  node: SurfaceNode,
  invariant: SecurityInvariantDefinition
): Array<SurfaceNode["controls"][number]["type"]> {
  const present = new Set(node.controls.map((control) => control.type));
  return invariant.requires.controls.filter((control) => !present.has(control));
}

function globLike(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

function uniqueNodes(nodes: SurfaceNode[]): SurfaceNode[] {
  return [...new Map(nodes.map((node) => [node.id, node])).values()];
}
